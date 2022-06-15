# justCTF 2022 Dark SOLs Writeup

## Challenge description

Brave Undead, you have proven yourself to me. Now, be one, with the Dark...

– [Nashandra](https://darksouls.fandom.com/wiki/Nashandra#:~:text=%22Brave%20Undead%2C%20you,%E2%80%94%20Nashandra)
```bash
nc darksols.nc.jctf.pro 1337
```

[Attachment](/release/darksols.zip): md5sum e3b74cfc83a0115e183d510f4f1dbc08

> I solve this challenge after the game ended.

## Analysis

By inspecting the challenge server's logic in [main.rs](source/darksols/src/main.rs#L236-L243), it is clear that the target of this challenge is to get 50000 lamports using the user account provided, whose initial balacne is 20 lamports. What's more, there are two programs already deployed except our solve program: [`darksols`](source/darksols/src/main.rs#L75) program and the [`evil-contract`](source/darksols/src/main.rs#L76) program. The `darksols` program contains a bunch of instructions that need further inspection, which must be the victim program. The `evil-contract` program is composed of [a single instrustion](source/evil-contract/src/evil-contract/evil-contract.c#L4-L18), whose job is to call the second account passed in as an executable program, using the remaining three accounts as the account list. Well, this does not make any sense at first glance. If I must call a program, I can just directly invoke the target in my own solve program, and this `evil-contract` remains unused. I cannot figure out how to use this given `evil-contract` at first, but I guess I might somewhere need it in the final exploit.

After deploying these two programs, there comes [some transcations](source/darksols/src/main.rs#L118) that initialize the environment and the darksol program. It sets the initial balance of the user account(20 lamports) and the vault account(1000000+ lamports), and creates two spl-token accounts, one is called `item` account and the other called `item` account.

Spl-token accounts are special accounts in Solana system. It is used to implement the `ERC20 Token` concept in the Ethereum ecosystem. The vital knowledge about this kind of account is its [Account structure](source/darksols/spl-token/src/state.rs#107-L116).

- The `mint` field shows which kind of token it belongs to, `item` token or `item1337` token in the case of this challenge. More information about this token, like the `mint_authority` or `total_supply`, is stored in the Mint Account it points to.
- The `amount` field shows how much amount of token is contained in this particular spl-token account.
- The `owner` field, obviously, shows who owns such amount of such token.

The `owner` field of spl-token accounts and the `owner` of Solana accounts are not the same concept. The `owner` of a Solana account is a system wide concept, denotes which account can modify the contents of this account. The `owner` field of spl-token accounts is just some data stored in a Solana account whose owner is the system spl-token program. Only the spl-token program can edit spl-token accounts. For more information on this, please refer to [Solana official documents](https://spl.solana.com/token)

```rust
pub struct Account {
    /// The mint associated with this account
    pub mint: Pubkey,
    /// The owner of this account.
    pub owner: Pubkey,
    /// The amount of tokens this account holds.
    pub amount: u64,
}

pub struct Mint {
    /// Optional authority used to mint new tokens. The mint authority may only be provided during
    /// mint creation. If no mint authority is present then the mint has a fixed supply and no
    /// further tokens may be minted.
    pub mint_authority: COption<Pubkey>,
    /// Total supply of tokens.
    pub supply: u64,
    /// Number of base 10 digits to the right of the decimal place.
    pub decimals: u8,
    /// Is `true` if this structure has been initialized
    pub is_initialized: bool,
    /// Optional authority to freeze token accounts.
    pub freeze_authority: COption<Pubkey>,
}
```

At the [end](source/darksols/src/main.rs#155) of the initialization, the `darksol` program's `INITIALIZE` [instruction](source/programs/src/darksols/darksols.c#398) is called. After some crital checks on the input accounts, it creates a `weapon` account, mint some tokens to two certain account, create another `sanity` account, and finally write the address of provided spl-token program into the `sanity` account.

```c
uint64_t handle_initialize(SolParameters* params) {
  ...
  create_weapons_account(params, payer, weapons);

  mint_to(params, mint, item, authority, 100);
  mint_to(params, mint_1337, item_1337, authority, 1);
  ...
  create_sanity_account(params, payer, sanity_acc);
  Sanity* temp = (Sanity*) sanity_acc->data;
  sol_memcpy(&temp->token, token->key, sizeof(SolPubkey));
}
```

Okay, have no idea what's going on right now. Let's look at the remaining instructions to figure out what this program want us to do. The `handle_create_player` seems an initialization operation as well, so I dive into this function next. After a bunch of checks on the input accounts, as usual, it creates a `player` account, initialize its relevant fields, create two spl-token accounts for the player, transfers some lamports into these two accounts, and finally initializes the two spl-token account.

The two `transfer()` function below is not transferring tokens, but rent fee that is mandatory to keep these two accounts alive. So after this `create_player` initialization, the two spl-token accounts for the player, one called `solve_item` account and the other `solve_item_1337` account, both has 0 token in it.

```c
uint64_t handle_create_player(SolParameters* params){
  ...
  create_player_account(params, payer, player_acc);
  Player* player = (Player*)player_acc->data;
  player->health = 0xff;
  player->mana = 0xff;
  const char* name = (const char*)(params->data + 9);
  sol_memcpy(player->name, name, 30);

  create_player_token_account(params, payer, solve_item, token->key, acct_seed, ITEM_TOKEN_SEED);
  create_player_token_account(params, payer, solve_item_1337, token->key, acct_seed_1337, ITEM_1337_TOKEN_SEED);

  transfer(params, vault, solve_item, MINIMUM_BALANCE);
  transfer(params, vault, solve_item_1337, MINIMUM_BALANCE);

  initialize_account(params, mint, solve_item, authority);
  initialize_account(params, mint_1337, solve_item_1337, authority);
}
```

The picture is still blurred at this time. I have to check the function `handle_fight` next. It first calculated a `player_attack` amount, according to the `solve_item` account's remaining token amount. There are two kinds of weapon available: the `item` spl-token associated weapon has attack value 1, and the `item1337` spl-token associated weapon has attack value 0x1337. Then we choose which monster to attack, and how many times to attack. In the end, certain reward for our fight is transferred back, in lamports.

```c
uint64_t handle_fight(SolParameters* params){
  SolAccountInfo* solve_item = &params->ka[3];
  Account* account = (Account*)solve_item->data;
  ...
  uint64_t player_attack = account->amount * weapon.attack;

  Monster monsters[9] = {
    { .attack = 1,      .reward = 1 },
    { .attack = 2,      .reward = 1 },
    { .attack = 4,      .reward = 2 },
    { .attack = 8,      .reward = 2 },
    { .attack = 16,     .reward = 3 },
    { .attack = 32,     .reward = 3 },
    { .attack = 64,     .reward = 4 },
    { .attack = 128,    .reward = 4 },
    { .attack = 0x1337, .reward = 0xd337 }
  };

  FightInstr* fight_instr = (FightInstr*)(params->data + 4);
  Monster monster = monsters[fight_instr->monster];
  uint64_t needed_health = 0;
  if (monster.attack > player_attack) {
    needed_health = (monster.attack - player_attack) * fight_instr->number;
  }
  uint64_t needed_mana = fight_instr->number;
  sol_assert(player->health >= needed_health);
  sol_assert(player->mana >= needed_mana);
  player->health -= needed_health;
  player->mana -= needed_mana;

  transfer(params, vault, payee, monster.reward * fight_instr->number);
}

```

The other two instrctions `handle_buy()` and `handle_sell()` can be simply taken as swapping between Solana lamports and spl-tokens, at 1 lamport to 1 `item` token and 0x1337 lamports to 1 `item1337` token ratio.

In order to earn 50000 lamports, we have to fight the monster whose attack value is 0x1337, and its reward is 0xd337(54071), which is enought to solve this challenge. But user only has 20 lamports at hand, who cannot afford to buy one `item1337` token to be able to fight the monster 1337.


## Unintended Solve 1

I studied the evil contract for a long time and think that players are supposed to somewhat fake the sanity account to point to this evil contract. But I just cannot figure out how to do that. I thought faking a sanity account which is owned by the program must use the given `initialize()` function in the `darksol` program, but in the `mint_to()` function it will pass 3 accounts to spl token account, which is not doable as the evil-contract accepts excatly 4 accounts.

But I somewhat do find that I can call the `initialize()` function as least, although the spl-token account must remains the system token account.

An idea occured to me that maybe I can use this `mint_to()` in `initialize()` to mint item1337 tokens to the player's iterm1337 account, and that is doable. I pass two `FAKE_SANITY` and `FAKE_WEAPON` to conform the `create_weapons_account` and `create_sanity_account` not to complain about account already exist error, and successfully mint one item1337 to the player's spl-account.

```c
uint64_t hacker(SolParameters *params)
{
  sol_assert(params->ka_num == ACCOUNT_CNT);
  sol_log("[+] About to pwn !");
  create_fake_player(params);
  initialize(params);
  fight(params);
  sol_log("[+] pwned !");
  return SUCCESS;
}
```

Then I just directly call the `fight` instruction to kill the monster 0x1337 and get the reward.

Relevant solve scripts lies in folder [sovle1](/solve1/). 

## Unintended Solve 2

I thought on the idea of faking the player's `solve_item` account and `solve_item_1337` account for a while. And I rechecked the `handle_fight` to see how it checks all its input accounts. I paid special attention on the `solve_item` address passed in, and surprisedly find that it only checks the spl-token's `owner` is the `authority`. 


```c
uint64_t handle_fight(SolParameters* params){
  SolAccountInfo* solve_item = &params->ka[3];
  ...
  Account* account = (Account*)solve_item->data;
  ...
  sol_assert(SolPubkey_same(&account->owner, authority->key));
  ...
}
```

That being said, I can directly use the origin `item1337` token account, which already has 1 `item1337` token in it, to fight and kill the monster1337.

```c
uint64_t hacker(SolParameters *params)
{
  sol_assert(params->ka_num == ACCOUNT_CNT);
  sol_log("[+] About to pwn !");
  create_player(params);
  fight1337(params);
  sol_log("[+] pwned !");
  return SUCCESS;
}
```

Relevant solve scripts lies in folder [sovle2](/solve2/). 

## Intended Solve

I finally come up with the intended solution, aka, using the `evil-contract`. It is correct that we need to fake the `sanity` account to the address of `evil-contract`. After that, we can get 1 `item1337` token by calling `sell()` instruction, which will delegate the call to the `evil-contarct`, which then swap the account order and call the `spl-token` program.

But how to? We cannot use the `initialize` function, which is the only place to edit the `sanity` account.

Some [checks](source/programs/src/darksols/darksols.c#L187) on the size of the `sanity` account serves as hint to me.

```c
sol_assert(sanity_acc->data_len == sizeof(Sanity));
```

I must find some data structure who has the same size of the `Sanity` structure(32 bytes), and it turns out that the `Player` struct comes to rescue.

```c
typedef struct {
  uint8_t health;
  uint8_t mana;
  char name[30];
} Player;
```

It is now clear that the length of the `name` buffer is carefully prepared just to make its size equal to 32 bytes. This `Player` account is owned by the program, and can pass all the checks on the original `sanity` account.

We just need to copy the last 30 bytes of pubkey of `evil-contract`(which is fixed) into the name buffer and use `fight` function to adjust the first two bytes until it equals to the first two bytes of the pubkey of `evil-contract`.

```c
uint64_t hacker(SolParameters *params)
{
  sol_assert(params->ka_num == ACCOUNT_CNT);
  sol_log("[+] About to pwn !");
  create_player(params);
  fight_to_sanity_health(params);
  buy(params);
  fight_to_sanity_mana(params);

  /* now player account can be used as sanity account
     use sell instruction to get 1 item1337 token */
  get_1337(params);

  /* now fight the 1337 monster and get the reward */
  fight1337(params);

  sol_log("[+] pwned !");
  return SUCCESS;
}
```
Relevant solve scripts lies in folder [sovle3](/solve3/). 

## Flag

`justCTF{if_y0u_m1ss_1t,_y0u_mu5t_b3_bl1nd!}`

## Side Notes

You can see it is really hard to write a **correct** and **secure** Solana program. There are just too many pitfalls in the Solana programming model, especailly you need to have careful checks on every account inputted, often take their logical relations into account. 