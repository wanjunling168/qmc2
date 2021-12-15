// QMC2-wasm.cpp : Defines the entry point for the application.
//

#include "QMC2-wasm.h"

#include <qmc2-crypto/KeyDec.h>
#include <qmc2-crypto/QMCDetection.h>
#include <qmc2-crypto/StreamCencrypt.h>

StreamCencrypt *createInstWidthEKey(std::string ekey_b64)
{
  StreamCencrypt *stream = new StreamCencrypt();
  KeyDec *key_dec = new KeyDec();
  key_dec->SetKey(ekey_b64.c_str(), ekey_b64.size());
  stream->SetKeyDec(key_dec);
  delete key_dec;
  return stream;
}

size_t sizeof_qmc_detection()
{
  return sizeof(qmc_detection);
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
