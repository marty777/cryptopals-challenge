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
	BIGNUM *r;
	BIGNUM *s;
};

class DSAClient
{
public:

	bool init_err;

	DSAClient(bool fixedG = false, const char *ghex = NULL);
	~DSAClient();

	bool generateUserKey(int userID);
	BIGNUM *getUserPublicKey(int userID);
	BIGNUM *getQ();
	BIGNUM *getP();
	BIGNUM *getG();
	BIGNUM *getX(int userID);

	bool generateSignature(ByteVector *data, DSASignature *signature, int userID, BIGNUM *return_k = NULL);
	bool verifySignature(ByteVector *data, DSASignature *signature, int userID, bool ignore_signature_bounds_check = false);

private:
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *g;
	std::vector<DSAUserKey> userkeys;

	bool generateParameters(bool fixedG = false, const char *ghex = NULL);
};

BIGNUM * DSA_xfromk(DSASignature *sig, ByteVector *data, BIGNUM *k, BIGNUM *q);
