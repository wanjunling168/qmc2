// QMC2-wasm.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <emscripten/bind.h>
#include <string>

#include <qmc2-crypto/StreamCencrypt.h>

namespace em = emscripten;

size_t sizeof_qmc_detection();
size_t offsetof_song_id();
size_t offsetof_error_msg();
size_t sizeof_song_id();
size_t sizeof_error_msg();

bool detectKeyEndPosition(
    /* qmc_detection* */ uintptr_t result,
    /* uin8_t* */ uintptr_t buf, size_t len);

StreamCencrypt *createInstWidthEKey(std::string ekey_b64, uint32_t seed, std::string mix_key_1, std::string mix_key_2);
void decryptStream(StreamCencrypt *sc, uintptr_t buf, size_t offset, size_t len);

EMSCRIPTEN_BINDINGS(QMC2_Crypto)
{
  em::class_<StreamCencrypt>("StreamCencrypt").constructor();

  em::function("sizeof_qmc_detection", &sizeof_qmc_detection);
  em::function("offsetof_song_id", &offsetof_song_id);
  em::function("offsetof_error_msg", &offsetof_error_msg);
  em::function("sizeof_song_id", &sizeof_song_id);
  em::function("sizeof_error_msg", &sizeof_error_msg);

  em::function("detectKeyEndPosition", &detectKeyEndPosition);

  em::function("createInstWidthEKey", &createInstWidthEKey, em::allow_raw_pointers());
  em::function("decryptStream", &decryptStream, em::allow_raw_pointers());
}
