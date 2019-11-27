#include "Set6.h"
#include <iostream>
#include "ByteVector.h"
#include "openssl\bn.h"
#include "BNUtility.h"
#include <vector>
#include "RSAClient.h"

using namespace std;

void Set6Challenge41() {
	vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	// create new client to represent oracle
	cout << "Creating oracle..." << endl;
	RSAClient client = RSAClient(1024);

	BIGNUM *E = BN_new();
	BIGNUM *N = BN_new();
	bn_add_to_ptrs(E, &bn_ptrs);
	bn_add_to_ptrs(N, &bn_ptrs);
	client.public_key(E, N);

	ByteVector secretmessage = ByteVector("This is a secret!", ASCII);
	ByteVector encrypted1 = ByteVector();

	// obtain unpadded ciphertext
	cout << "Creating initial ciphertext C..." << endl;
	client.encrypt_bv(&secretmessage, &encrypted1);
	BIGNUM *ciphertext = bn_from_bytevector(&encrypted1, &bn_ptrs);
	
	// S = random number mod N != 1
	cout << "Generating random S..." << endl;
	BIGNUM *S = BN_new();
	bn_add_to_ptrs(S, &bn_ptrs);
	if (!BN_rand_range(S, N)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	// if S = 1 -> S = 2
	if (BN_cmp(S, BN_value_one()) == 0) {
		if (!BN_add(S, S, BN_value_one())) {
			cout << "BN error" << endl;
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return;
		}
	}

	// set C2 = ((S**E mod N) C) mod N
	cout << "Creating second ciphertext C'..." << endl;
	BIGNUM * ciphertext2 = BN_new();
	bn_add_to_ptrs(ciphertext2, &bn_ptrs);

	if (!BN_mod_exp(ciphertext2, S, E, N, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mod_mul(ciphertext2, ciphertext2, ciphertext, N, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}

	// confirm C' != C (for the purposes of our oracle that won't decrypt the same message twice)
	if (BN_cmp(ciphertext, ciphertext2) == 0) {
		cout << "C and C' are equal" << endl;
	}
	else {
		cout << "C and C' are not equal" << endl;
	}

	// obtain decryption of C2
	cout << "Decrypting C'..." << endl;
	ByteVector c2 = ByteVector();
	ByteVector p2 = ByteVector();
	bn_to_bytevector(ciphertext2, &c2);
	client.decrypt_bv(&c2, &p2);

	// determine actual plaintext
	cout << "Obtaining original plaintext..." << endl;
	BIGNUM *plaintext2 = bn_from_bytevector(&p2, &bn_ptrs);
	BIGNUM *s_inverse = BN_new();
	bn_add_to_ptrs(s_inverse, &bn_ptrs);
	if (!BN_mod_inverse(s_inverse, S, N, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	BIGNUM *plaintext = BN_new();
	bn_add_to_ptrs(plaintext, &bn_ptrs);
	if (!BN_mod_mul(plaintext, plaintext2, s_inverse, N, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	ByteVector result = ByteVector();
	bn_to_bytevector(plaintext, &result);
	cout << "Result: " << endl << result.toStr(ASCII) << endl;

	
	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
}

void Set6Challenge42() {
	RSAClient client1 = RSAClient(512);
	ByteVector bv = ByteVector("The length of the data D shall not be more than k-11 octets, which is positive since the length k of the modulus is at least 12 octets. This limitation guarantees that the length of the padding string PS is at least eight octets, which is a security condition.", ASCII);
	ByteVector encrypted = ByteVector();
	ByteVector decrypted = ByteVector();

	client1.encrypt_bv(&bv, &encrypted, true, 0);
	cout << "Got here " << endl;
	client1.decrypt_bv(&encrypted, &decrypted, true, 0);
	cout << "Result:" << endl << decrypted.toStr(ASCII) << endl;
}

int Set6() {
	cout << "### SET 6 ###" << endl;
	cout << "Set 6 Challenge 41" << endl;
	Set6Challenge41();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	return 0;
}