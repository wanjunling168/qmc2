#pragma once

#include <cstddef>
#include <cstdint>

constexpr size_t footer_detection_size = 0x40;
constexpr size_t encrypted_key_size_v1 = 364;
constexpr size_t encrypted_key_size_v2 = 704;

struct qmc_detection
{
  // ekey start position - it can be negative.
  // 0: start from the eof buffer
  // negative: starts x bytes before eof buffer
  // positive: starts x bytes after eof buffer
  int32_t ekey_position;

  size_t ekey_len;

  // decimal representation of UINT64_MAX is 21 digits
  // Use 24 here to align to memory.
  char song_id[24];

  char error_msg[80];
};

bool detect_key_end_position(qmc_detection &result, uint8_t *buf, size_t len);
