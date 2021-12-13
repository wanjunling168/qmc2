#pragma once

#include <cstdint>
#include <cstddef>

constexpr size_t footer_detection_size = 0x40;
constexpr size_t encrypted_key_size_v1 = 364;
constexpr size_t encrypted_key_size_v2 = 704;

struct qmc_detection {
	// ekey start position - it can be negative.
	// 0: start from the eof buffer
	// negative: starts x bytes before eof buffer
	// positive: starts x bytes after eof buffer
	int32_t ekey_position;

	size_t ekey_len;

	char error_msg[40];
};

bool detect_key_end_position(qmc_detection& result, uint8_t* buf, size_t len);
