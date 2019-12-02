#include "DSAClient.h"
#include "ByteVector.h"
#include "BNUtility.h"
#include "ByteEncryption.h"
#include <vector>

DSAClient::DSAClient(bool fixedG, const char* ghex)
{
	init_err = false;

	// init p, q and g. p and q are predetermined and fixed
	if (!generateParameters(fixedG, ghex)) {
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
			BIGNUM *y = BN_dup(userkeys[i].y);
			return y;
		}
	}
	return NULL;
}

BIGNUM *DSAClient::getQ() {
	BIGNUM *ret = BN_dup(q);
	return ret;
}

BIGNUM *DSAClient::getP() {
	BIGNUM *ret = BN_dup(p);
	return ret;
}

BIGNUM *DSAClient::getG() {
	BIGNUM *ret = BN_dup(g);
	return ret;
}

// for testing recovery from known k
BIGNUM *DSAClient::getX(int userID) {
	for (size_t i = 0; i < userkeys.size(); i++) {
		if (userkeys[i].user_id == userID) {
			BIGNUM *x = BN_dup(userkeys[i].x);
			return x;
		}
	}
	return NULL;
}

// if return_k is not null, recieves a copy of k
bool DSAClient::generateSignature(ByteVector *data, DSASignature *signature, int userID, BIGNUM *return_k) {
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	// get user keys
	for (size_t i = 0; i < userkeys.size(); i++) {
		if (userkeys[i].user_id == userID) {
			x = BN_dup(userkeys[i].x);
			y = BN_dup(userkeys[i].y);
		}
	}

	if (x == NULL || y == NULL) {
		return false;
	}

	// From wikipedia, it looks like SHA-1 and SHA-2 are used with DSA. I only have SHA-1 implemented so...
	ByteVector hash = ByteVector();
	ByteEncryption::sha1(data, &hash);
	// note that the hash may need to be truncated depending on N
	int n = BN_num_bits(q);
	if (hash.length() * 8 > n) {
		printf("Truncating hash %d %d\n", n, hash.length() * 8);

	}

	BN_CTX *ctx = BN_CTX_new();
	std::vector<BIGNUM *> bn_ptrs;
	bn_add_to_ptrs(x, &bn_ptrs);
	bn_add_to_ptrs(y, &bn_ptrs);

	BIGNUM *zero = bn_from_word(0, &bn_ptrs);
	BIGNUM *s = bn_from_word(0, &bn_ptrs);
	BIGNUM *r = BN_new();
	bn_add_to_ptrs(r, &bn_ptrs);

	while (true) {
		// generate k as random on {1, q-1}
		BIGNUM *k = BN_new();
		BIGNUM *two = bn_from_word(2, &bn_ptrs);
		BIGNUM *range = BN_dup(q);
		bn_add_to_ptrs(k, &bn_ptrs);
		bn_add_to_ptrs(range, &bn_ptrs);
		if (!BN_sub(range, range, two)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}
		if (!BN_rand_range(k, range)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}
		if (!BN_add(k, k, BN_value_one())) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}

		if (return_k != NULL) {
			BN_copy(return_k, k);
		}

		// generate r =( g ^ k % p) % q
		if (!BN_mod_exp(r, g, k, p, ctx)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}
		if (!BN_mod(r, r, q, ctx)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}

		// generate s = k^-1 * (Hash(data) + xr) % q
		// if s = 0, go around the loop with another k
		BIGNUM *k_inverse = BN_new();
		bn_add_to_ptrs(k, &bn_ptrs);
		if (!BN_mod_inverse(k_inverse, k, q, ctx)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}
		BN_copy(s, r);
		bn_add_to_ptrs(s, &bn_ptrs);
		BIGNUM *hash_bn = bn_from_bytevector(&hash, &bn_ptrs);
		if (!BN_mod_mul(s, s, x, q, ctx)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}
		if (!BN_mod_add(s, s, hash_bn, q, ctx)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}
		if (!BN_mod_mul(s, s, k_inverse, q, ctx)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}
		
		if (BN_cmp(s, zero) != 0) {
			break;
		}
	}
	if (signature->s == NULL) {
		signature->s = BN_dup(s);
	}
	else {
		BN_copy(signature->s, s);
	}
	if (signature->r == NULL) {
		signature->r = BN_dup(r);
	}
	else {
		BN_copy(signature->r, r);
	}
	if (signature->s == NULL || signature->r == NULL) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
	return true;
}
bool DSAClient::verifySignature(ByteVector *data, DSASignature *signature, int userID, bool ignore_signature_bounds_check) {

	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	// get user keys
	for (size_t i = 0; i < userkeys.size(); i++) {
		if (userkeys[i].user_id == userID) {
			x = BN_dup(userkeys[i].x);
			y = BN_dup(userkeys[i].y);
		}
	}

	if (x == NULL || y == NULL) {
		return false;
	}

	BIGNUM *r = BN_dup(signature->r);
	BIGNUM *s = BN_dup(signature->s);
	if (r == NULL || s == NULL) {
		if (r != NULL) {
			BN_free(r);
		}
		if (s != NULL) {
			BN_free(s);
		}
		BN_free(x);
		BN_free(y);
		return false;
	}

	// From wikipedia, it looks like SHA-1 and SHA-2 are used with DSA. I only have SHA-1 implemented so...
	ByteVector hash = ByteVector();
	ByteEncryption::sha1(data, &hash);
	// note that the hash may need to be truncated depending on N
	int n = BN_num_bits(q);
	if (hash.length() * 8 > n) {
		printf("Truncating hash %d %d\n", n, hash.length() * 8);

	}

	BN_CTX *ctx = BN_CTX_new();
	std::vector<BIGNUM *> bn_ptrs;
	bn_add_to_ptrs(x, &bn_ptrs);
	bn_add_to_ptrs(y, &bn_ptrs);
	bn_add_to_ptrs(r, &bn_ptrs);
	bn_add_to_ptrs(s, &bn_ptrs);

	BIGNUM *zero = bn_from_word(0, &bn_ptrs);

	// verify 0 < r < q and 0 < s < q
	if (!ignore_signature_bounds_check) { // ignore switch added 
		if (BN_cmp(zero, r) >= 0 || BN_cmp(r, q) >= 0 || BN_cmp(zero, s) >= 0 || BN_cmp(s, q) >= 0) {
			BN_CTX_free(ctx);
			bn_free_ptrs(&bn_ptrs);
			return false;
		}
	}
	
	// compute w = s^-1 mod q
	BIGNUM *w = BN_new();
	bn_add_to_ptrs(w, &bn_ptrs);
	if (!BN_mod_inverse(w, s, q, ctx)) {
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return false;
	}

	BIGNUM *hash_bn = bn_from_bytevector(&hash, &bn_ptrs);

	// compute u1 = hash * w % q
	BIGNUM *u1 = BN_new();
	bn_add_to_ptrs(u1,&bn_ptrs);
	if (!BN_mod_mul(u1, hash_bn, w, q, ctx)) {
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return false;
	}

	// compute u2 = r*w % q
	BIGNUM *u2 = BN_new();
	bn_add_to_ptrs(u2, &bn_ptrs);
	if (!BN_mod_mul(u2, r, w, q, ctx)) {
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return false;
	}

	// compute v =( g^u1 * y^u2 % p) % q
	BIGNUM *v = BN_new();
	BIGNUM *temp1 = BN_new();
	BIGNUM *temp2 = BN_new();
	bn_add_to_ptrs(v, &bn_ptrs);
	bn_add_to_ptrs(temp1, &bn_ptrs);
	bn_add_to_ptrs(temp2, &bn_ptrs);
	if (!BN_mod_exp(temp1, g, u1, p, ctx)) {
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return false;
	}
	if (!BN_mod_exp(temp2, y, u2, p, ctx)) {
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return false;
	}
	if (!BN_mod_mul(v, temp1, temp2, p, ctx)) {
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return false;
	}
	if (!BN_mod(v, v, q, ctx)) {
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return false;
	}

	if (BN_cmp(v, r) == 0) {
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return true;
	}

	BN_CTX_free(ctx);
	bn_free_ptrs(&bn_ptrs);
	return false;
}

// We're mostly using pre-generated ones
bool DSAClient::generateParameters(bool fixedG, const char *ghex) {
	
	BN_CTX *ctx = BN_CTX_new();
	std::vector<BIGNUM *> bn_ptrs;

	ByteVector predeterminedP = ByteVector("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", HEX);
	ByteVector predeterminedQ = ByteVector("f4f47f05794b256174bba6e9b396a7707e563c5b", HEX);
	ByteVector predeterminedG = ByteVector("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", HEX);

	p = bn_from_bytevector(&predeterminedP);
	q = bn_from_bytevector(&predeterminedQ);
	if (fixedG) {
		if (ghex != NULL) {
			g = BN_new();
			if (!BN_hex2bn(&g, ghex)) {
				return false;
			}
		}
		else {
			g = bn_from_bytevector(&predeterminedG);
		}
	}
	else {
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
	}

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
	return true;
}

// for challenge 43
BIGNUM * DSA_xfromk(DSASignature *sig, ByteVector *data, BIGNUM *k, BIGNUM *q) {
	std::vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	ByteVector hash = ByteVector();
	ByteEncryption::sha1(data, &hash);
	BIGNUM *hash_bn = bn_from_bytevector(&hash, &bn_ptrs);
	BIGNUM *r_inv = BN_new();
	BIGNUM *x = BN_new();
	bn_add_to_ptrs(r_inv, &bn_ptrs);
	if (!BN_mod_inverse(r_inv, sig->r, q, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_free(x);
		return NULL;
	}

	if (!BN_mod_mul(x, sig->s, k, q, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_free(x);
		return NULL;
	}
	if (!BN_mod_sub(x, x, hash_bn, q, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_free(x);
		return NULL;
	}
	if (!BN_mod_mul(x, x, r_inv, q, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_free(x);
		return NULL;
	}

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);

	return x;
}