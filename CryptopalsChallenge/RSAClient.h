#pragma once
#include <openssl\bn.h>
#include "ByteVector.h"

class RSAClient
{

public:
	
	bool init_err;

	RSAClient(int bits, bool verbose = false);
	~RSAClient();
	bool encrypt_bv(ByteVector *input, ByteVector *encrypted, bool padded = false, int padtype = 0);
	bool decrypt_bv(ByteVector *encrypted, ByteVector *output, bool padded = false, int padtype = 0);
	void print_vals();
	bool public_key(BIGNUM *e_out, BIGNUM *n_out);

private:
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
};

