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
  SimpleMakeKey(CONST_SIMPLE_KEY_SEED, 8, simple_key_buf);
#if _DEBUG
  // Nothing here.
#endif

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
  char MixKey1[] = CONST_MIX_KEY_1;
  char MixKey2[] = CONST_MIX_KEY_2;

  std::vector<char> decode_key_1;
  std::vector<char> decode_key_2;
  TC_Tea tea;
  if (!tea.decrypt(MixKey1, reinterpret_cast<char *>(key.data()) + 18, key.size() - 18, decode_key_1))
  {
    key.resize(0);
    fprintf(stderr, "ERROR: EncV2 stage 1 key decode failed.\n");
    return false;
  }

  if (!tea.decrypt(MixKey2, decode_key_1.data(), decode_key_1.size(), decode_key_2))
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
