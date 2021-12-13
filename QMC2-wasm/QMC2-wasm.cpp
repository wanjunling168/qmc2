// QMC2-wasm.cpp : Defines the entry point for the application.
//

#include "QMC2-wasm.h"

uintptr_t createInstWidthEKey(std::string ekey_b64) {
	StreamCencrypt* stream = new StreamCencrypt();
	KeyDec* key_dec = new KeyDec();
	key_dec->SetKey(ekey_b64.c_str(), ekey_b64.size());
	stream->SetKeyDec(key_dec);
	delete key_dec;
	return reinterpret_cast<uintptr_t>(stream);
}

size_t sizeof_qmc_detection() {
	return sizeof(qmc_detection);
}

bool detectKeyEndPosition(uintptr_t result, uintptr_t buf, size_t len) {
	return detect_key_end_position(
		*reinterpret_cast<qmc_detection*>(result),
		reinterpret_cast<uint8_t*>(buf),
		len
	);
}

void decryptStream(uintptr_t sc, uintptr_t buf, size_t offset, size_t len) {
	// uint64_t offset, uint8_t* buf, size_t len
	reinterpret_cast<StreamCencrypt*>(sc)->StreamDecrypt(
		uint64_t(offset),
		reinterpret_cast<uint8_t*>(buf),
		len
	);
}
