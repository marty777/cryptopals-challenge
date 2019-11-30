#pragma once
#include <openssl\bn.h>
#include "ByteVector.h"
#include <vector>

BIGNUM *bn_from_word(unsigned long long word, std::vector<BIGNUM *> *ptrs = NULL);

BIGNUM *bn_from_bytevector(ByteVector *src, std::vector<BIGNUM *> *ptrs = NULL);

int bn_handle_error(int bn_func_return, char *msg = NULL, std::vector<BIGNUM *> *ptrs = NULL, BN_CTX *ctx = NULL);

void bn_to_bytevector(BIGNUM *src, ByteVector *dest);

void bn_print(BIGNUM * b, bv_str_format format);

void bn_add_to_ptrs(BIGNUM *bn, std::vector<BIGNUM *> *ptrs);

void bn_free_ptrs(std::vector<BIGNUM *> *ptrs);

bool bn_invmod(BIGNUM *in, BIGNUM *modulus, BIGNUM *invmod);

bool bn_gcdextended(BIGNUM *a, BIGNUM *b, BIGNUM *x, BIGNUM *y, BIGNUM *gcd);

bool bn_nth_root(BIGNUM *a, BIGNUM *n, BIGNUM *nearest_nth_root);