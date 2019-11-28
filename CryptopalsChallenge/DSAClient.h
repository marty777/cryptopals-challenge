#pragma once
#include <openssl\bn.h>
#include <vector>
#include "ByteVector.h"

struct DSAUserKey {
	int user_id;
	BIGNUM *x;
	BIGNUM *y;
};

struct DSASignature {
	ByteVector r;
	ByteVector s;
};

class DSAClient
{
public:

	bool init_err;

	DSAClient();
	~DSAClient();

	bool generateUserKey(int userID);
	BIGNUM *getUserPublicKey(int userID);

	bool generateSignature(ByteVector *data, DSASignature *signature, int userID);
	bool verifySignature(ByteVector *data, DSASignature *signature, int userID);

private:
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *g;
	std::vector<DSAUserKey> userkeys;

	bool generateParameters();
};

