#include "qmc2-crypto/KeyDec.h"

#include <util/tc_base64.h>
#include <util/tc_tea.h>

#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

using tars::TC_Base64;
using tars::TC_Tea;

#if __has_include("qmc2-crypto/KeyDec.local.h")
#include "qmc2-crypto/KeyDec.local.h"
#endif

#ifndef CONST_SIMPLE_KEY_SEED
#define CONST_SIMPLE_KEY_SEED (0)
#define CONST_MIX_KEY_1                                                                                                \
  {                                                                                                                    \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00                     \
  }
#define CONST_MIX_KEY_2                                                                                                \
  {                                                                                                                    \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00                     \
  }
#endif

uint8_t DEFAULT_MIX_KEY1[0x10] = CONST_MIX_KEY_1;
uint8_t DEFAULT_MIX_KEY2[0x10] = CONST_MIX_KEY_2;

KeyDec::KeyDec() : seed(CONST_SIMPLE_KEY_SEED)
{
  memcpy(mix_key1, DEFAULT_MIX_KEY1, 0x10);
  memcpy(mix_key2, DEFAULT_MIX_KEY2, 0x10);
}

void KeyDec::InitDecryptionKey(uint8_t seed, uint8_t *mix_key1, uint8_t *mix_key2)
{
  this->seed = seed;
  memcpy(this->mix_key1, mix_key1, 0x10);
  memcpy(this->mix_key2, mix_key2, 0x10);
}

void SimpleMakeKey(uint8_t seed, size_t len, uint8_t *buf)
{
  for (int i = 0; len > i; ++i)
  {
    buf[i] = (uint8_t)(fabs(tan((float)seed + (double)i * 0.1)) * 100.0);
  }
}

KeyDec::~KeyDec()
{
  Uninit();
}

void KeyDec::Uninit()
{
  if (key)
  {
    delete[] key;
    key = nullptr;
  }

  key_len = 0;
}

void KeyDec::GetKey(uint8_t *&key_out, size_t &key_len_out)
{
  if (key && key_len > 0)
  {
    key_len_out = key_len;
    key_out = new uint8_t[key_len];
    memcpy(key_out, key, key_len);
  }
  else
  {
    key_len_out = 0;
  }
}

void KeyDec::SetKey(const char *ekey, const size_t key_size)
{
  Uninit();
  size_t decode_len = key_size / 4 * 3 + 4;

  std::vector<uint8_t> ekey_decoded;
  ekey_decoded.resize(decode_len);

  uint8_t simple_key_buf[8] = {0};
  SimpleMakeKey(seed, 8, simple_key_buf);

  TC_Base64 b64;
  decode_len = b64.decode(ekey, key_size, ekey_decoded.data());
  ekey_decoded.resize(decode_len);

  if (decode_len < 8)
  {
    fprintf(stderr, "ERROR: decoded key size is too small, got %x.\n", int(decode_len));
    return;
  }

  if (isEncV2(ekey_decoded))
  {
    if (!DecryptV2Key(ekey_decoded))
    {
      fprintf(stderr, "ERROR: decode EncV2 failed.\n");
      return;
    }

    decode_len = ekey_decoded.size();
  }

  uint8_t tea_key[16] = {};
  for (int i = 0; i < 16; i += 2)
  {
    tea_key[i + 0] = simple_key_buf[i / 2];
    tea_key[i + 1] = ekey_decoded[i / 2];
  }

  key = new uint8_t[decode_len * 2]();

  // Copy first 8 bytes
  memcpy(key, ekey_decoded.data(), 8u);

  // Copy the rest
  std::vector<char> decrypted_buf;
  TC_Tea tea;
  tea.decrypt(reinterpret_cast<const char *>(tea_key), reinterpret_cast<const char *>(ekey_decoded.data()) + 8,
              decode_len - 8, decrypted_buf);
  key_len = decrypted_buf.size() + 8;
  memcpy(&key[8], decrypted_buf.data(), decrypted_buf.size());
}

bool KeyDec::isEncV2(std::vector<uint8_t> &key)
{
  return memcmp(key.data(), "QQMusic EncV2,Key:", 18) == 0;
}

bool KeyDec::DecryptV2Key(std::vector<uint8_t> &key)
{
  std::vector<char> decode_key_1;
  std::vector<char> decode_key_2;
  TC_Tea tea;
  if (!tea.decrypt((const char *)mix_key1, reinterpret_cast<char *>(key.data()) + 18, key.size() - 18, decode_key_1))
  {
    key.resize(0);
    fprintf(stderr, "ERROR: EncV2 stage 1 key decode failed.\n");
    return false;
  }

  if (!tea.decrypt((const char *)mix_key2, decode_key_1.data(), decode_key_1.size(), decode_key_2))
  {
    key.resize(0);
    fprintf(stderr, "ERROR: EncV2 stage 2 key decode failed.\n");
    return false;
  }

  TC_Base64 b64;
  auto decode_len = b64.decode(decode_key_2.data(), decode_key_2.size(), key.data());
  key.resize(decode_len);

  if (decode_len < 8)
  {
    fprintf(stderr, "ERROR: EncV2 key size is too small, got %x.\n", int(decode_len));
    return false;
  }

  return true;
}
