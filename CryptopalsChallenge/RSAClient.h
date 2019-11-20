#pragma once
#include <openssl\bn.h>
class RSAClient
{

public:
	
	RSAClient();
	~RSAClient();
	int invmod(BIGNUM *a, BIGNUM *modulus, BIGNUM *invmod);

private:
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;

	
};

