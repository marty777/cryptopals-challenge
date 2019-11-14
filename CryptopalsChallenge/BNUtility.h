#pragma once
#include <openssl\bn.h>
#include "ByteVector.h"

BIGNUM *bn_from_word(unsigned long long word);

BIGNUM *bn_from_bytevector(ByteVector *src);

void bn_to_bytevector(BIGNUM *src, ByteVector *dest);

void bn_print(BIGNUM * b, bv_str_format format);