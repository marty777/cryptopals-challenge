#include "DSAClient.h"
#include "ByteVector.h"
#include "BNUtility.h"

DSAClient::DSAClient()
{
	init_err = false;

	// init p, q and g. p and q are predetermined and fixed
	if (!generateParameters()) {
		init_err = true;
		return;
	}
}


DSAClient::~DSAClient()
{
	BN_free(p);
	BN_free(q);
	BN_free(g);
}


bool DSAClient::generateUserKey(int userID) {
	// check if this id has been previously used
	for (size_t i = 0; i < userkeys.size(); i++) {
		if (userkeys[i].user_id == userID) {
			return false;
		}
	}

	DSAUserKey key;
	key.user_id = userID;

	BN_CTX *ctx = BN_CTX_new();
	std::vector<BIGNUM *> bn_ptrs;

	key.x = BN_new();
	key.y = BN_new();
	if (key.x == NULL || key.y == NULL) {
		BN_CTX_free(ctx);
		return false;
	}

	// x is random on {1..q-1}
	BIGNUM *temp = BN_dup(q);
	bn_add_to_ptrs(temp, &bn_ptrs);
	BIGNUM *two = bn_from_word(2, &bn_ptrs);
	if (!BN_sub(temp, temp, two)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}
	if (!BN_rand_range(key.x, temp)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}
	if (!BN_add(key.x, key.x, BN_value_one())) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	// y = g ^ x % p
	if (!BN_mod_exp(key.y, g, key.x, p, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	userkeys.push_back(key);

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
	return true;
}

// returns null if not found or an allocation error occurred
BIGNUM *DSAClient::getUserPublicKey(int userID) {
	for (size_t i = 0; i < userkeys.size(); i++) {
		if (userkeys[i].user_id == userID) {
			BIGNUM *x = BN_dup(userkeys[i].x);
			return x;
		}
	}
	return NULL;
}

// We're mostly using pre-generated ones
bool DSAClient::generateParameters() {
	
	BN_CTX *ctx = BN_CTX_new();
	std::vector<BIGNUM *> bn_ptrs;

	ByteVector predeterminedP = ByteVector("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", HEX);
	ByteVector predeterminedQ = ByteVector("f4f47f05794b256174bba6e9b396a7707e563c5b", HEX);
	//ByteVector predeterminedG = ByteVector("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", HEX);

	p = bn_from_bytevector(&predeterminedP);
	q = bn_from_bytevector(&predeterminedQ);
	//g = bn_from_bytevector(&predeterminedG);

	// g isn't as labourious to generate compared to p and q
	// h random integer on {2..p-2}
	BIGNUM *h = BN_new();
	BIGNUM *range = BN_dup(p);
	bn_add_to_ptrs(h, &bn_ptrs);
	bn_add_to_ptrs(range, &bn_ptrs);
	BIGNUM *four = bn_from_word(4, &bn_ptrs);
	BIGNUM *two = bn_from_word(2, &bn_ptrs);
	if (!BN_sub(range, range, four)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}
	if (!BN_rand_range(h, range)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}
	if (!BN_add(h, h, two)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	// g = h ^ (p-1)/q % p
	BIGNUM *exp = BN_dup(p);
	bn_add_to_ptrs(exp, &bn_ptrs);
	if (!BN_sub(exp, exp, BN_value_one())) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}
	if (!BN_div(exp, NULL, exp, q, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	g = BN_new();
	if (!BN_mod_exp(g, h, exp, p, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
	return true;
}