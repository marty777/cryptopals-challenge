#pragma once
#include <openssl\bn.h>
#include <vector>

struct DSAUserKey {
	int user_id;
	BIGNUM *x;
	BIGNUM *y;
};

class DSAClient
{
public:

	bool init_err;

	DSAClient();
	~DSAClient();

	bool generateUserKey(int userID);
	BIGNUM *getUserPublicKey(int userID);

private:
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *g;
	std::vector<DSAUserKey> userkeys;

	bool generateParameters();
};

