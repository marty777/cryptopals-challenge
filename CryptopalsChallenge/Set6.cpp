#include "Set6.h"
#include <iostream>
#include "ByteVector.h"
#include "ByteEncryption.h"
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

	vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	cout << "Testing RSA block padding..." << endl;
	RSAClient client1 = RSAClient(1024);
	ByteVector bv = ByteVector("The length of the data D shall not be more than k-11 octets, which is positive since the length k of the modulus is at least 12 octets. This limitation guarantees that the length of the padding string PS is at least eight octets, which is a security condition.", ASCII);
	ByteVector encrypted = ByteVector();
	ByteVector decrypted = ByteVector();

	cout << "Encrypting multiblock message..." << endl;
	client1.encrypt_bv(&bv, &encrypted, true, 1);
	cout << "Decrypting multiblock message..." << endl;
	client1.decrypt_bv(&encrypted, &decrypted, true, 1);
	cout << "Result " << (bv.equal(&decrypted) ? " (matches original):" : " (does not match original):") << endl << decrypted.toStr(ASCII) << endl;

	cout << "Testing MD4 RSA signing of data..." << endl;
	ByteVector signature = ByteVector();
	client1.sign_bv(&bv, &signature);
	if (client1.verify_signature_bv(&signature, &bv)) {
		cout << "Public key of signature validates digest" << endl;
	}
	else {
		cout << "Public key of signature does not validate digest" << endl;
	}

	cout << "Forging signature..." << endl;
	ByteVector himom = ByteVector("hi mom", ASCII);
	ByteVector hash = ByteVector();
	ByteEncryption::md4(&himom, &hash);
	ByteVector data = ByteVector(hash.length() + 5);
	data[0] = 0x00;
	data[1] = 0x01;
	data[2] = 0xff;
	data[3] = 0x00; // end of padding
	data[4] = 0x02; // digest specification field in our signature format indicating MD4
	hash.copyBytesByIndex(&data, 0, hash.length(), 5);

	BIGNUM *data_bn = bn_from_bytevector(&data, &bn_ptrs);
	BIGNUM *three = bn_from_word(3, &bn_ptrs);
	BIGNUM *cube_root_N = BN_new();
	bn_add_to_ptrs(cube_root_N, &bn_ptrs);
	

	BIGNUM *clientE = BN_new();
	BIGNUM *clientN = BN_new();
	bn_add_to_ptrs(clientE, &bn_ptrs);
	bn_add_to_ptrs(clientN, &bn_ptrs);
	client1.public_key(clientE, clientN);

	bn_nth_root(clientN, three, cube_root_N);
	
	// right-pad forged signature with zeroes to proper length for a block less 1.
	// The less 1 is because of the initial zero byte in our padding. For it to 
	// be re-appended after cubing, the result needs to be one byte short
	int N_bytes = BN_num_bytes(clientN);
	int data_bytes = BN_num_bytes(data_bn);
	if (N_bytes <= data_bytes) { // we've picked a bad key size or something in the setup
		cout << "Something's wrong" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	// data_bn should be one byte shorter than N
	if (!BN_lshift(data_bn, data_bn, (N_bytes - data_bytes - 1)*8)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}

	BIGNUM *cuberoot = BN_new();
	bn_add_to_ptrs(cuberoot, &bn_ptrs);
	if (!bn_nth_root(data_bn, three, cuberoot)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_add(cuberoot, cuberoot, BN_value_one())) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	
	// we could check this result and maybe tweak it slightly if it's off, but let's live dangerously.

	ByteVector forgedsig = ByteVector();
	bn_to_bytevector(cuberoot, &forgedsig);

	if (client1.verify_signature_bv(&forgedsig, &himom)) {
		cout << "Forged valid signature for string '" << himom.toStr(ASCII) << "'" << endl;
	}
	else {
		cout << "Did not forge valid signature for string '" << himom.toStr(ASCII) << "'" << endl;
	}

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
}

void Set6Challenge43() {

}

int Set6() {
	cout << "### SET 6 ###" << endl;
	cout << "Set 6 Challenge 41" << endl;
	Set6Challenge41();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 6 Challenge 42" << endl;
	Set6Challenge42();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 6 Challenge 43" << endl;
	Set6Challenge43();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	return 0;
}