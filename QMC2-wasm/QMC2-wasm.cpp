// QMC2-wasm.cpp : Defines the entry point for the application.
//

#include "QMC2-wasm.h"

#include <qmc2-crypto/KeyDec.h>
#include <qmc2-crypto/QMCDetection.h>
#include <qmc2-crypto/StreamCencrypt.h>

#include <stddef.h>
#include <string.h>

StreamCencrypt *createInstWidthEKey(std::string ekey_b64, uint32_t seed, std::string mix_key_1, std::string mix_key_2)
{
  StreamCencrypt *stream = new StreamCencrypt();
  KeyDec *key_dec = new KeyDec();
  if (mix_key_1.length() == 16 && mix_key_2.length() == 16)
  {
    key_dec->InitDecryptionKey(seed, (uint8_t *)mix_key_1.c_str(), (uint8_t *)mix_key_2.c_str());
  }
  key_dec->SetKey(ekey_b64.c_str(), strlen(ekey_b64.c_str()));
  stream->SetKeyDec(key_dec);
  delete key_dec;
  return stream;
}

size_t sizeof_qmc_detection()
{
  return sizeof(qmc_detection);
}

size_t offsetof_song_id()
{
  return offsetof(qmc_detection, song_id);
}

size_t offsetof_error_msg()
{
  return offsetof(qmc_detection, error_msg);
}

size_t sizeof_song_id()
{
  return sizeof(qmc_detection::song_id);
}

size_t sizeof_error_msg()
{
  return sizeof(qmc_detection::error_msg);
}

bool detectKeyEndPosition(uintptr_t result, uintptr_t buf, size_t len)
{
  return detect_key_end_position(*reinterpret_cast<qmc_detection *>(result), reinterpret_cast<uint8_t *>(buf), len);
}

void decryptStream(StreamCencrypt *sc, uintptr_t buf, size_t offset, size_t len)
{
  // uint64_t offset, uint8_t* buf, size_t len
  sc->StreamDecrypt(uint64_t(offset), reinterpret_cast<uint8_t *>(buf), len);
}
