#include "RSAClient.h"
#include "BNUtility.h"
#include <iostream>


RSAClient::RSAClient(int bits, bool verbose)
{
	init_err = false;
	// might want to add a proper way to seed the RNG
	// generate p and q
	p = BN_new();
	q = BN_new();
	if (p == NULL || q == NULL) {
		init_err = true;
		return;
	}
	if (verbose) {
		std::cout << "Generating P..." << std::endl;
	}
	BN_generate_prime_ex(p, bits, 0, NULL, NULL, NULL);
	if (verbose) {
		std::cout << "Generating Q..." << std::endl;
	}
	BN_generate_prime_ex(q, bits, 0, NULL, NULL, NULL);
	if (verbose) {
		std::cout << "Computing N..." << std::endl;
	}
	// compute n
	BN_CTX *ctx = BN_CTX_new();
	if (ctx == NULL) {
		init_err = true;
		return;
	}
	n = BN_new();
	if (n == NULL) {
		init_err = true;
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mul(n, p, q, ctx)) {
		init_err = true;
		BN_CTX_free(ctx);
		return;
	}

	if (verbose) {
		std::cout << "n = " << BN_bn2dec(n) << std::endl;
	}

	e = BN_new();
	if (e == NULL) {
		init_err = true;
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_set_word(e, 3)) {
		init_err = true;
		BN_CTX_free(ctx);
		return;
	}

	d = BN_new();
	if (d == NULL) {
		init_err = true;
		BN_CTX_free(ctx);
		return;
	}

	BIGNUM *p_1 = BN_new();
	BIGNUM *q_1 = BN_new();
	BIGNUM *et = BN_new();
	if (p_1 == NULL || q_1 == NULL || et == NULL) {
		init_err = true;
		if (p_1 != NULL) {
			BN_free(p_1);
		}
		if (q_1 != NULL) {
			BN_free(q_1);
		}
		if (et != NULL) {
			BN_free(et);
		}
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_sub(p_1, p, BN_value_one())) {
		init_err = true;
		BN_free(p_1);
		BN_free(q_1);
		BN_free(et);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_sub(q_1, q, BN_value_one())) {
		init_err = true;
		BN_free(p_1);
		BN_free(q_1);
		BN_free(et);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mul(et, p_1, q_1, ctx)) {
		init_err = true;
		BN_free(p_1);
		BN_free(q_1);
		BN_free(et);
		BN_CTX_free(ctx);
		return;
	}
	// done with p_1, q_1
	BN_free(p_1);
	BN_free(q_1);

	// d invmod(e, et)
	if (!bn_invmod(e, et, d)) {
		init_err = true;
		BN_free(et);
		BN_CTX_free(ctx);
		return;
	}

	if (verbose) {
		std::cout << "d = " << BN_bn2dec(d) << std::endl;
	}

	// done with et
	BN_free(et);

	if (verbose) {
		std::cout << "Initialization complete." << std::endl;
	}

	BN_CTX_free(ctx);
}

// returns false on BIGNUM error
bool RSAClient::encrypt_bv(ByteVector *input, ByteVector *encrypted) {
	BN_CTX *ctx = BN_CTX_new();
	std::vector<BIGNUM *> bn_ptrs;
	BIGNUM *out = BN_new();
	bn_add_to_ptrs(out, &bn_ptrs);

	BIGNUM *in = bn_from_bytevector(input, &bn_ptrs);

	if (!BN_mod_exp(out, in, e, n, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	bn_to_bytevector(out, encrypted);

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
	return true;
}
// returns false on BIGNUM error
bool RSAClient::decrypt_bv(ByteVector *encrypted, ByteVector *output) {
	BN_CTX *ctx = BN_CTX_new();
	std::vector<BIGNUM *> bn_ptrs;
	BIGNUM *out = BN_new();
	bn_add_to_ptrs(out, &bn_ptrs);

	BIGNUM *in = bn_from_bytevector(encrypted, &bn_ptrs);

	if (!BN_mod_exp(out, in, d, n, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	bn_to_bytevector(out, output);

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
	return true;
}


RSAClient::~RSAClient()
{
	if (p != NULL) {
		BN_free(p);
	}
	if (q != NULL) {
		BN_free(q);
	}
	if (n != NULL) {
		BN_free(n);
	}
	if (e != NULL) {
		BN_free(e);
	}
	if (d != NULL) {
		BN_free(d);
	}
}

void RSAClient::print_vals() {
	printf("P:\t%s\n", BN_bn2hex(p));
	printf("Q:\t%s\n", BN_bn2hex(q));
	printf("N:\t%s\n", BN_bn2hex(n));
	printf("D:\t%s\n", BN_bn2hex(d));
}

// copies e and n to initialized BIGNUMs e_out and n_out
// returns false if e or n are not initialized
bool RSAClient::public_key(BIGNUM *e_out, BIGNUM *n_out) {
	if (e == NULL || n == NULL) {
		return false;
	}
	BN_copy(e_out, e);
	BN_copy(n_out, n);
	return true;
}

