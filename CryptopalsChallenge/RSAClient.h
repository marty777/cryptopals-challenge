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
	bool sign_bv(ByteVector *input, ByteVector *signature);
	bool verify_signature_bv(ByteVector *signature, ByteVector *data);
	void print_vals();
	bool public_key(BIGNUM *e_out, BIGNUM *n_out);
	bool decryptionIsOdd(ByteVector *input, bool padded = false, int padtype = 0);


private:
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
};

