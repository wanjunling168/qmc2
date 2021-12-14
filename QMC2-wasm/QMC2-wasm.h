// QMC2-wasm.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <emscripten/bind.h>
#include <string>

#include "../QMC2-crypto/include/qmc2-crypto/KeyDec.h"
#include "../QMC2-crypto/include/qmc2-crypto/QMCDetection.h"
#include "../QMC2-crypto/include/qmc2-crypto/StreamCencrypt.h"

namespace em = emscripten;

size_t sizeof_qmc_detection();
bool detectKeyEndPosition(
    /* qmc_detection* */ uintptr_t result,
    /* uin8_t* */ uintptr_t buf, size_t len);

StreamCencrypt *createInstWidthEKey(std::string ekey_b64);
void decryptStream(StreamCencrypt *sc, uintptr_t buf, size_t offset, size_t len);

EMSCRIPTEN_BINDINGS(QMC2_Crypto)
{
  em::class_<StreamCencrypt>("StreamCencrypt").constructor();

  em::function("sizeof_qmc_detection", &sizeof_qmc_detection);
  em::function("detectKeyEndPosition", &detectKeyEndPosition);

  em::function("createInstWidthEKey", &createInstWidthEKey, em::allow_raw_pointers());
  em::function("decryptStream", &decryptStream, em::allow_raw_pointers());
}
