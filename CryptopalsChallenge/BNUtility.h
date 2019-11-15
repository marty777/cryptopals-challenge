#pragma once
#include <openssl\bn.h>
#include "ByteVector.h"
#include <vector>

BIGNUM *bn_from_word(unsigned long long word, std::vector<BIGNUM *> *ptrs = NULL);

BIGNUM *bn_from_bytevector(ByteVector *src, std::vector<BIGNUM *> *ptrs = NULL);

void bn_to_bytevector(BIGNUM *src, ByteVector *dest);

void bn_print(BIGNUM * b, bv_str_format format);

void bn_add_to_ptrs(BIGNUM *bn, std::vector<BIGNUM *> *ptrs);

void bn_free_ptrs(std::vector<BIGNUM *> *ptrs);