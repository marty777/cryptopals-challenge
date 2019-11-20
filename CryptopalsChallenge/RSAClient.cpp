#include "RSAClient.h"
#include "BNUtility.h"


RSAClient::RSAClient()
{
}


RSAClient::~RSAClient()
{
}


int RSAClient::invmod(BIGNUM *in, BIGNUM *modulus, BIGNUM *invmod) {

	if (BN_cmp(modulus, BN_value_one())) {
		BN_zero(invmod);
		return 0;
	}

	std::vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *m0 = BN_dup(modulus);
	bn_add_to_ptrs(m0, &bn_ptrs);

	BIGNUM *m1 = BN_dup(modulus);
	bn_add_to_ptrs(m0, &bn_ptrs);

	BIGNUM *a = BN_dup(in);
	bn_add_to_ptrs(a, &bn_ptrs);

	BIGNUM *q = BN_new();
	BIGNUM *r = BN_new();
	BIGNUM *t = BN_new();
	BIGNUM *temp = BN_new();
	bn_add_to_ptrs(q, &bn_ptrs);
	bn_add_to_ptrs(r, &bn_ptrs);
	bn_add_to_ptrs(t, &bn_ptrs);
	bn_add_to_ptrs(temp, &bn_ptrs);

	BIGNUM *y, *x;
	y = bn_from_word(0, &bn_ptrs);
	x = bn_from_word(1, &bn_ptrs);

	int ret;

	// while a > 1
	while (BN_cmp(a, BN_value_one()) > 0) {
		// (q,r) = a/m1
		if ((ret = BN_div(q, r, a, m1, ctx)) != 0) {
			BN_CTX_free(ctx);
			bn_free_ptrs(&bn_ptrs);
			return ret;
		}
		// t = m1
		if (BN_copy(t, m1) == NULL) {
			BN_CTX_free(ctx);
			bn_free_ptrs(&bn_ptrs);
			return -1;
		}

		// m1 = r
		if (BN_copy(m1, r) == NULL) {
			BN_CTX_free(ctx);
			bn_free_ptrs(&bn_ptrs);
			return -1;
		}
		// a = t
		if (BN_copy(a, t) == NULL) {
			BN_CTX_free(ctx);
			bn_free_ptrs(&bn_ptrs);
			return -1;
		}
		// t = y
		if (BN_copy(t, y) == NULL) {
			BN_CTX_free(ctx);
			bn_free_ptrs(&bn_ptrs);
			return -1;
		}

		// y = x - q * y
		if ((ret = BN_mul(temp, q, y, ctx)) != 0) {
			BN_CTX_free(ctx);
			bn_free_ptrs(&bn_ptrs);
			return ret;
		}
		if ((ret = BN_sub(y, x, temp)) != 0) {
			BN_CTX_free(ctx);
			bn_free_ptrs(&bn_ptrs);
			return ret;
		}
	}

	if (BN_is_negative(x)) {
		if ((ret = BN_add(x, x, m0)) != 0) {
			BN_CTX_free(ctx);
			bn_free_ptrs(&bn_ptrs);
			return ret;
		}
	}
 
	// return x
	if (BN_copy(invmod, x) == NULL) {
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return -1;
	}

	BN_CTX_free(ctx);
	bn_free_ptrs(&bn_ptrs);
	return 0;
}