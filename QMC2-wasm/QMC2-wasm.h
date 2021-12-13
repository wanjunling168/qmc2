// QMC2-wasm.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <emscripten/bind.h>
#include <string>

#include "../QMC2-crypto/include/qmc2-crypto/StreamCencrypt.h"
#include "../QMC2-crypto/include/qmc2-crypto/KeyDec.h"
#include "../QMC2-crypto/include/qmc2-crypto/QMCDetection.h"

uintptr_t createInstWidthEKey(std::string ekey_b64);
size_t sizeof_qmc_detection();
bool detectKeyEndPosition(uintptr_t result, uintptr_t buf, size_t len);
void decryptStream(uintptr_t sc, uintptr_t buf, size_t offset, size_t len);

EMSCRIPTEN_BINDINGS(QMC2_Crypto) {
  emscripten::function("createInstWidthEKey", &createInstWidthEKey);
  emscripten::function("detectKeyEndPosition", &detectKeyEndPosition);
  emscripten::function("sizeof_qmc_detection", &sizeof_qmc_detection);
  emscripten::function("decryptStream", &decryptStream);
}
