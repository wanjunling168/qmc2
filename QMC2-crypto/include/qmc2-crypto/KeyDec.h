#pragma once
#include "IKeyDec.h"
#include <cstddef>
#include <vector>

class KeyDec : public IKeyDec
{
public:
  KeyDec(){};
  ~KeyDec();

  virtual void GetKey(uint8_t *&key, size_t &key_size) override;
  virtual void SetKey(const char *key, const size_t key_size) override;

private:
  uint8_t *key = nullptr;
  size_t key_len = 0;

  void Uninit();

  static bool isEncV2(std::vector<uint8_t> &key);
  static bool DecryptV2Key(std::vector<uint8_t> &key);
};
