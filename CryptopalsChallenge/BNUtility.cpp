#include "BNUtility.h"
#include <iostream>
#include <vector>

BIGNUM *bn_from_word(unsigned long long word, std::vector<BIGNUM *> *ptrs) {
	BIGNUM *b = BN_new();
	if (ptrs != NULL) {
		bn_add_to_ptrs(b, ptrs);
	}
	BN_set_word(b, word);
	return b;
}

BIGNUM *bn_from_bytevector(ByteVector *src, std::vector<BIGNUM *> *ptrs) {
	BIGNUM *b = BN_new();
	if (ptrs != NULL) {
		bn_add_to_ptrs(b, ptrs);
	}
	BN_bin2bn(src->dataPtr(), src->length(), b);
	return b;
}

// if an error occured, print msg and free BIGNUM ptrs and ctx. Returns the error code
int bn_handle_error(int bn_func_return, char *msg, std::vector<BIGNUM *> *ptrs, BN_CTX *ctx) {
	if (!bn_func_return) {
		if (msg != NULL) {
			std::cout << msg << std::endl;
		}
		if (ptrs != NULL) {
			bn_free_ptrs(ptrs);
		}
		if (ctx != NULL) {
			BN_CTX_free(ctx);
		}
	}
	return bn_func_return;
}

void bn_to_bytevector(BIGNUM *src, ByteVector *dest) {
	size_t len = BN_num_bytes(src);
	unsigned char* bin = (unsigned char*)malloc(len * sizeof(unsigned char));
	BN_bn2bin(src, bin);
	dest->resize(len);
	for (size_t i = 0; i < len; i++) {
		(*dest)[i] = bin[i];
	}
	free(bin);
}

void bn_print(BIGNUM * b, bv_str_format format) {
	ByteVector bv = ByteVector();
	bn_to_bytevector(b, &bv);
	char* buf = bv.toStr(format);
	std::cout << buf << std::endl;
}

void bn_add_to_ptrs(BIGNUM *bn, std::vector<BIGNUM *> *ptrs) {
	for (size_t i = 0; i < ptrs->size(); i++) {
		if ((*ptrs)[i] == bn) {
			return;
		}
	}
	ptrs->push_back(bn);
}

void bn_free_ptrs(std::vector<BIGNUM *> *ptrs) {
	while (ptrs->size() > 0) {
		BIGNUM *bn = (*ptrs)[ptrs->size() - 1];
		BN_free(bn);
		ptrs->pop_back();
	}
}

// returns false on BIGNUM error or if in and modulus are not coprime.
// implementation based on code from https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
bool bn_invmod(BIGNUM *in, BIGNUM *modulus, BIGNUM *invmod) {
	std::vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BIGNUM *g = BN_new();
	bn_add_to_ptrs(x, &bn_ptrs);
	bn_add_to_ptrs(y, &bn_ptrs);
	bn_add_to_ptrs(g, &bn_ptrs);

	if (!bn_gcdextended(in, modulus, x, y, g)) {
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return false;
	}
	if (BN_cmp(g, BN_value_one()) != 0) {
		//std::cout << "inverse doesn't exist. GCD = " << BN_bn2dec(g) << std::endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return false;
	}

	// inverse = (x%m + m) % m. The +m is to ensure the inverse is positive
	if (!BN_mod(invmod, x, modulus, ctx)) {
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return false;
	}
	if (!BN_mod_add(invmod, invmod, modulus, modulus, ctx)) {
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return false;
	}

	BN_CTX_free(ctx);
	bn_free_ptrs(&bn_ptrs);
	return true;

}

// recursive function for extended euclidean algorithm
// returns false on BIGNUM error
// implementation based on code from https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
bool bn_gcdextended(BIGNUM *a, BIGNUM *b, BIGNUM *x, BIGNUM *y, BIGNUM *gcd) {
	BN_CTX *ctx = BN_CTX_new();
	std::vector<BIGNUM *> bn_ptrs;

	BIGNUM *zero = bn_from_word(0, &bn_ptrs);
	if (BN_cmp(a, zero) == 0) {
		BN_set_word(x, 0);
		BN_set_word(y, 1);
		BN_copy(gcd, b);
		return true;
	}

	BIGNUM *x1 = BN_new();
	BIGNUM *y1 = BN_new();
	BIGNUM *a1 = BN_new();
	BIGNUM *gcd1 = BN_new();
	BIGNUM *temp1 = BN_new();
	BIGNUM *temp2 = BN_new();
	bn_add_to_ptrs(x1, &bn_ptrs);
	bn_add_to_ptrs(y1, &bn_ptrs);
	bn_add_to_ptrs(a1, &bn_ptrs);
	bn_add_to_ptrs(gcd1, &bn_ptrs);
	bn_add_to_ptrs(temp1, &bn_ptrs);
	bn_add_to_ptrs(temp2, &bn_ptrs);
	// a1 = b % a
	if (!BN_mod(a1, b, a, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	if (!bn_gcdextended(a1, a, x1, y1, gcd1)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	BN_copy(gcd, gcd1);
	// x = y1 - (b/a) * x1
	if (!BN_div(temp1, temp2, b, a, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}
	if (!BN_mul(temp2, temp1, x1, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}
	if (!BN_sub(x, y1, temp2)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}
	// y = x1
	BN_copy(y, x1);

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
}

// determines nearest integer nth root of a using a binary search
// i.e. a ** n <= nearest_nth_root < (a + 1) ** n.
bool bn_nth_root(BIGNUM *a, BIGNUM *n, BIGNUM *nearest_nth_root) {

	//printf("Nth root start %s %s\n", BN_bn2dec(a), BN_bn2dec(n));

	std::vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	// high = 1
	BIGNUM *high = bn_from_word(1, &bn_ptrs);
	BIGNUM *two = bn_from_word(2, &bn_ptrs);
	BIGNUM *temp = BN_new();
	bn_add_to_ptrs(temp, &bn_ptrs);
	while (true) {
		// break when high ** n > a
		if (!BN_exp(temp, high, n, ctx)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}
		if (BN_cmp(temp, a) > 0) {
			break;
		}
		// high *= 2
		if (!BN_mul(high, high, two, ctx)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}
	}

	// low = high/2
	BIGNUM *low = BN_new();
	bn_add_to_ptrs(low, &bn_ptrs);
	if (!BN_div(low, NULL, high, two, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}


	//printf("Got here %s %s\n", BN_bn2dec(high), BN_bn2dec(low));

	BIGNUM *mid = BN_new();
	bn_add_to_ptrs(mid, &bn_ptrs);
	
	while (true) {
		// break if low >= high
		// mid = low + high / 2
		if (!BN_add(temp, low, high)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}
		if (!BN_div(mid, NULL, temp, two, ctx)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}

		//printf("Loop %s %s %s\n", BN_bn2dec(high), BN_bn2dec(mid), BN_bn2dec(low));

		// temp = mid ** n
		if (!BN_exp(temp, mid, n, ctx)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}
		// if low < mid && mid ** n < a
		if (BN_cmp(low, mid) < 0 && BN_cmp(temp, a) < 0) {
			// low = mid
			if(BN_copy(low, mid) == NULL) {
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return false;
			}
		}
		// else if high > mid && mid ** n > a 
		else if (BN_cmp(high, mid) > 0 && BN_cmp(temp, a) > 0)  {
			// high = mid
			if (BN_copy(high, mid) == NULL) {
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return false;
			}
		}
		else {
			// nailed mid
			if (BN_copy(nearest_nth_root, mid) == NULL) {
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return false;
			}
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return true;
		}

		// break if low >= high
		if (BN_cmp(low, high) >= 0) {
			break;
		}
	}

	// not an exact match on mid. Return mid+1
	if (!BN_add(nearest_nth_root, mid, BN_value_one())) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
	return true;
}