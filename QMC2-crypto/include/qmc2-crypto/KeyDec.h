#pragma once
#include "IKeyDec.h"
#include <cstddef>
#include <vector>

class KeyDec : public IKeyDec
{
public:
  KeyDec();
  ~KeyDec();

  virtual void GetKey(uint8_t *&key, size_t &key_size) override;
  virtual void SetKey(const char *key, const size_t key_size) override;
  void InitDecryptionKey(uint8_t seed, const uint8_t *mix_key1, const uint8_t *mix_key2);

private:
  uint8_t *key = nullptr;
  size_t key_len = 0;

  uint8_t seed;
  uint8_t mix_key1[16];
  uint8_t mix_key2[16];

  void Uninit();

  static bool isEncV2(std::vector<uint8_t> &key);
  bool DecryptV2Key(std::vector<uint8_t> &key);
};
