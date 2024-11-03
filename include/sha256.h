#pragma once
#include "common.h"

#define BLOCK_SIZE 64

uint8_t* sha_256(const uint8_t *message, const uint64_t& m_len_bytes);
bool SHA_check_vector();