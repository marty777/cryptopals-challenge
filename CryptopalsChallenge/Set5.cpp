#include "Set5.h"
#include "ByteVector.h"
#include "ByteEncryption.h"
#include "Utility.h"
#include <iostream>
#include "openssl\bn.h"
#include "openssl\err.h"
#include "BNUtility.h"
#include <vector>
#include <assert.h>
#include "SRPServer.h"
#include "RSAClient.h"

using namespace std;

string getOpenSSLError()
{
	BIO *bio = BIO_new(BIO_s_mem());
	ERR_print_errors(bio);
	char *buf;
	size_t len = BIO_get_mem_data(bio, &buf);
	string ret(buf, len);
	BIO_free(bio);
	return ret;
}

void Set5Challenge33() {

	vector<BIGNUM *> bn_ptrs;

	BN_CTX *ctx = BN_CTX_new();
	// initial test parameters
	BIGNUM *p1 = bn_from_word(37, &bn_ptrs);
	BIGNUM *g1 = bn_from_word(5, &bn_ptrs);
	// random integer 0 <= a1 < 37
	BIGNUM *a1 = BN_new();
	bn_add_to_ptrs(a1, &bn_ptrs);
	if (!BN_rand_range(a1, p1)) {
		cout << "Error encountered" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	BIGNUM *A1 = BN_new();
	bn_add_to_ptrs(A1, &bn_ptrs);
	if (!BN_mod_exp(A1, g1, a1, p1, ctx)) {
		cout << "Error encountered" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	// random integer 0 <= b1 < 37
	BIGNUM *b1 = BN_new();
	bn_add_to_ptrs(b1, &bn_ptrs);
	if (!BN_rand_range(b1, p1)) {
		cout << "Error encountered" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	BIGNUM *B1 = BN_new();
	bn_add_to_ptrs(B1, &bn_ptrs);
	if (!BN_mod_exp(B1, g1, b1, p1, ctx)) {
		cout << "Error encountered" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}

	BIGNUM *sA = BN_new();
	bn_add_to_ptrs(sA, &bn_ptrs);
	if (!BN_mod_exp(sA, B1, a1, p1, ctx)) {
		cout << "Error encountered" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	BIGNUM *sB = BN_new();
	bn_add_to_ptrs(sB, &bn_ptrs);
	if (!BN_mod_exp(sA, A1, b1, p1, ctx)) {
		cout << "Error encountered" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}

	if (!BN_cmp(sA, sB) == 0) {
		cout << "Small test of (A**b) % p equal to (B**a) % p" << endl;
	}
	else {
		cout << "Small test of (A**b) % p not equal to (B**a) % p" << endl;
	}

	bn_free_ptrs(&bn_ptrs);
	
	// NIST parameters
	ByteVector bigP = ByteVector("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", HEX);
	BIGNUM *p = bn_from_bytevector(&bigP, &bn_ptrs);
	BIGNUM *g = bn_from_word(2, &bn_ptrs);
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *A = BN_new();
	BIGNUM *B = BN_new();
	bn_add_to_ptrs(a, &bn_ptrs);
	bn_add_to_ptrs(b, &bn_ptrs);
	bn_add_to_ptrs(A, &bn_ptrs);
	bn_add_to_ptrs(B, &bn_ptrs);
	if (!BN_rand_range(a, p)) {
		cout << "Error encountered" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_rand_range(b, p)) {
		cout << "Error encountered" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mod_exp(A, g, a, p, ctx)) {
		cout << "Error encountered" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mod_exp(B, g, b, p, ctx)) {
		cout << "Error encountered" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	BIGNUM *s1 = BN_new();
	bn_add_to_ptrs(s1, &bn_ptrs);
	if (!BN_mod_exp(s1, A, b, p, ctx)) {
		cout << "Error encountered" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	BIGNUM *s2 = BN_new();
	bn_add_to_ptrs(s2, &bn_ptrs);
	if (!BN_mod_exp(s2, B, a, p, ctx)) {
		cout << "Error encountered" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_cmp(sA, sB) == 0) {
		cout << "Large test of (A**b) % p equal to (B**a) % p" << endl;
	}
	else {
		cout << "Large test of (A**b) % p not equal to (B**a) % p" << endl;
	}

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
}

void Set5Challenge34() {

	vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	// field prime and generator parameters
	ByteVector bigP = ByteVector("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", HEX);
	BIGNUM *p = bn_from_bytevector(&bigP, &bn_ptrs);
	BIGNUM *g = bn_from_word(2, &bn_ptrs);

	// participants A and B
	BIGNUM *a_private_key = BN_new();
	BIGNUM *a_public_key = BN_new();
	bn_add_to_ptrs(a_private_key, &bn_ptrs);
	bn_add_to_ptrs(a_public_key, &bn_ptrs);
	if (!BN_rand_range(a_private_key, p)) {
		cout << "Error encountered" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	if (!BN_mod_exp(a_public_key, g, a_private_key, p, ctx)) {
		cout << "Error encountered" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	BIGNUM *b_private_key = BN_new();
	BIGNUM *b_public_key = BN_new();
	bn_add_to_ptrs(b_private_key, &bn_ptrs);
	bn_add_to_ptrs(b_public_key, &bn_ptrs);
	if (!BN_rand_range(b_private_key, p)) {
		cout << "Error encountered" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	if (!BN_mod_exp(b_public_key, g, b_private_key, p, ctx)) {
		cout << "Error encountered" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}

	// simulate regular key exchange and encryption/decryption
	// A->B (p,g,a_public_key)
	// B->A (b_public_key)
	// A->B (message encrypted with AES-CBC using key derived from (b_public_key ** a_private_key) % p)
	// B->A decrypted message from A, encrypted with key derived from (a_public_key ** b_private_key) % p)
	cout << "No eavesdropping:" << endl;
	cout << "Simulating exchange of DH parameters and public keys..." << endl;
	cout << "Sending encrypted message from A to B..." << endl;
	ByteVector message = ByteVector("This is a test message", ASCII);
	ByteVector fromAtoB = ByteVector();
	ByteEncryption::challenge34Encrypt(p, b_public_key, a_private_key, &message, &fromAtoB);

	cout << "B decrypting message from A...";
	ByteVector recievedByB = ByteVector();
	ByteEncryption::challenge34Decrypt(p, a_public_key, b_private_key, &fromAtoB, &recievedByB);
	if (recievedByB.equal(&message)) {
		cout << "passed" << endl;
	}
	else {
		cout << "failed" << endl;
	}

	cout << "Sending confirmation encrypted message from B to A..." << endl;
	ByteVector fromBtoA = ByteVector();
	ByteEncryption::challenge34Encrypt(p, a_public_key, b_private_key, &recievedByB, &fromBtoA);

	cout << "A decrypting message from B...";
	ByteVector recievedByA = ByteVector();
	ByteEncryption::challenge34Decrypt(p, b_public_key, a_private_key, &fromBtoA, &recievedByA);
	if (recievedByA.equal(&message)) {
		cout << "passed" << endl;
	}
	else {
		cout << "failed" << endl;
	}

	// simulate MITM with parameter injection
	// A->M (p,g,a_public_key)
	// M->B (p,g,p)
	// B->M (b_public_key)
	// M->A (p)
	// A->M (message encrypted with AES-CBC using key derived from (p ** a_private_key) % p (equivalent to 0))
	// M->B (relay message from A)
	// B->M (decrypted message from A, encrypted with key derived from (p ** b_private_key) % p (equivalent to 0)
	cout << endl << "With eavesdropping:" << endl;
	cout << "Simulating exchange of DH parameters and public keys..." << endl;
	ByteVector message2 = ByteVector("This is a test message that M shouldn't see", ASCII);
	cout << "Sending encrypted message from A to M to B..." << endl;
	ByteVector fromAtoMtoB = ByteVector();
	ByteEncryption::challenge34Encrypt(p, p, a_private_key, &message2, &fromAtoMtoB);

	cout << "B decrypting message from A via M...";
	ByteVector recievedByBfromM = ByteVector();
	ByteEncryption::challenge34Decrypt(p, p, b_private_key, &fromAtoMtoB, &recievedByBfromM);
	if (recievedByBfromM.equal(&message2)) {
		cout << "passed" << endl;
	}
	else {
		cout << "failed" << endl;
	}
	BIGNUM *m_cheat_private_key = bn_from_word(1, &bn_ptrs);
	cout << "M decrypting intercepted message from A...";
	ByteVector interceptedFromA = ByteVector();
	ByteEncryption::challenge34Decrypt(p, p, m_cheat_private_key, &fromAtoMtoB, &interceptedFromA);
	if (interceptedFromA.equal(&message2)) {
		cout << "passed" << endl;
	}
	else {
		cout << "failed" << endl;
	}

	cout << "Sending confirmation encrypted message from B to A via M..." << endl;
	ByteVector fromBtoAviaM = ByteVector();
	ByteEncryption::challenge34Encrypt(p, p, b_private_key, &recievedByBfromM, &fromBtoAviaM);

	cout << "A decrypting message from B via M...";
	ByteVector recievedByAfromM = ByteVector();
	ByteEncryption::challenge34Decrypt(p, p, a_private_key, &fromAtoMtoB, &recievedByBfromM);
	if (recievedByBfromM.equal(&message2)) {
		cout << "passed" << endl;
	}
	else {
		cout << "failed" << endl;
	}
	cout << "M decrypting intercepted message from B...";
	ByteVector interceptedFromB = ByteVector();
	ByteEncryption::challenge34Decrypt(p, p, m_cheat_private_key, &fromBtoAviaM, &interceptedFromB);
	if (interceptedFromB.equal(&message2)) {
		cout << "passed" << endl;
	}
	else {
		cout << "failed" << endl;
	}

	cout << "Decrypted message from B by M:" << endl << interceptedFromB.toStr(ASCII) << endl;

	BN_CTX_free(ctx);
	bn_free_ptrs(&bn_ptrs);
}

void Set5Challenge35() {

	vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	// field prime and generator parameters
	ByteVector bigP = ByteVector("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", HEX);
	BIGNUM *p = bn_from_bytevector(&bigP, &bn_ptrs);
	BIGNUM *g1 = bn_from_word(1, &bn_ptrs);
	BIGNUM *gp = bn_from_bytevector(&bigP, &bn_ptrs);
	BIGNUM *gp_minus_1 = bn_from_bytevector(&bigP, &bn_ptrs);
	if (!BN_sub_word(gp_minus_1, 1)) {
		cout << "Error encounterd" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}

	// if g == 1 -> public key A = 1 ^ (private_key) % p == 1 (for p > 1). When computing s, 1 ^ private_key % p is 1.
	// if g == p -> public key A = p ^ (private_key) % p == 0. s = 0 ^ private_key % p == 0.
	// if g = p-1 -> public key A = (p-1) ^ (private_key) % p. 
	//		(p-1)*(p-1) % p = 1 and (1 * p-1) % p = p-1, so p-1 raised to any power mod p is either 1 or p-1 depending on whether the exponent is even. 
	//		p is intended to be a large prime so A = p-1.
	//		When computing s (p-1) ^ private_key % p is either 1 or p-1 depending on whether the private key is odd or even.

	// below isn't a full simulation of the key exchange and message interception, just a verification of the above by testing a message sent in one direction
	BIGNUM *a_private_key = BN_new();
	BIGNUM *b_private_key = BN_new();
	BIGNUM *a_public_key_g1 = BN_new();
	BIGNUM *a_public_key_gp = BN_new();
	BIGNUM *a_public_key_gp_minus_1 = BN_new();
	BIGNUM *s1 = BN_new();
	BIGNUM *s0 = BN_new();
	BIGNUM *sp_minus_1 = BN_new();
	bn_add_to_ptrs(a_private_key, &bn_ptrs);
	bn_add_to_ptrs(b_private_key, &bn_ptrs);
	bn_add_to_ptrs(a_public_key_g1, &bn_ptrs);
	bn_add_to_ptrs(a_public_key_gp, &bn_ptrs);
	bn_add_to_ptrs(a_public_key_gp_minus_1, &bn_ptrs);
	bn_add_to_ptrs(s1, &bn_ptrs);
	bn_add_to_ptrs(s0, &bn_ptrs);
	bn_add_to_ptrs(sp_minus_1, &bn_ptrs);
	BN_one(s1); // s1 = 1
	BN_zero(s0); // s0 = 0
	BN_copy(sp_minus_1, gp_minus_1); // sp_minus_1 = p-1

	// generate private keys
	if (!BN_rand_range(a_private_key, p) || !BN_rand_range(b_private_key, p)) {
		cout << "Error encountered" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}

	// case g = 1
	cout << "Case g == 1: " << endl;
	// A generates public key (as does B, but we're omitting that part). B sends message to A, intercepted by M encrypted with key based on s
	cout << "Generating public key for participant A..." << endl;
	if (!BN_mod_exp(a_public_key_g1, g1, a_private_key, p, ctx)) {
		cout << "Error encountered" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	// Encrypt message to A from B knowing public key
	cout << "Encrypting test message from B to A..." << endl;
	ByteVector message = ByteVector("This is a message from A to B that M shouldn't see.", ASCII);
	ByteVector encrypted_g1 = ByteVector();
	ByteEncryption::challenge34Encrypt(p, a_public_key_g1, b_private_key, &message, &encrypted_g1);

	// decrypt as M knowing g = 1 -> s = 1
	cout << "Testing decryption as participant M...";
	ByteVector decrypted_g1 = ByteVector();
	ByteEncryption::challenge35Decrypt(p, s1, &encrypted_g1, &decrypted_g1);
	cout << (message.equal(&decrypted_g1) ? "passed" : "failed") << endl;
	
	// case g = p
	cout << "Case g == p: " << endl;
	// A generates public key 
	cout << "Generating public key for participant A..." << endl;
	if (!BN_mod_exp(a_public_key_gp, gp, a_private_key, p, ctx)) {
		cout << "Error encountered" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	// Encrypt message to A from B knowing public key
	cout << "Encrypting test message from B to A..." << endl;
	ByteVector encrypted_gp = ByteVector();
	ByteEncryption::challenge34Encrypt(p, a_public_key_gp, b_private_key, &message, &encrypted_gp);

	// decrypt as M knowing g = p -> s = 0
	cout << "Testing decryption as participant M...";
	ByteVector decrypted_gp = ByteVector();
	ByteEncryption::challenge35Decrypt(p, s0, &encrypted_gp, &decrypted_gp);
	cout << (message.equal(&decrypted_gp) ? "passed" : "failed") << endl;

	// case g = p-1
	cout << "Case g == p - 1: " << endl;
	// A generates public key 
	cout << "Generating public key for participant A..." << endl;
	if (!BN_mod_exp(a_public_key_gp_minus_1, gp_minus_1, a_private_key, p, ctx)) {
		cout << "Error encountered" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	// Encrypt message to A from B knowing public key
	cout << "Encrypting test message from B to A..." << endl;
	ByteVector encrypted_gp_minus_1 = ByteVector();
	ByteEncryption::challenge34Encrypt(p, a_public_key_gp_minus_1, b_private_key, &message, &encrypted_gp_minus_1);

	// decrypt as M knowing g = p-1 -> s = 1 or s = p-1
	cout << "Testing decryption as participant M..." << endl;
	ByteVector decrypted_gp_minus_1 = ByteVector();
	bool success = false;
	if (!ByteEncryption::challenge35Decrypt(p, s1, &encrypted_gp_minus_1, &decrypted_gp_minus_1)) {
		cout << "Decryption assuming s = 0 failed. Retrying with s = p - 1..." << endl;
		if (!ByteEncryption::challenge35Decrypt(p, sp_minus_1, &encrypted_gp_minus_1, &decrypted_gp_minus_1)) {
			cout << "Decryption assuming s = p - 1 failed." << endl;
		}
		else {
			cout << "Decryption succeeded with s = p - 1." << endl;
			success = true;
		}
	}
	else {
		cout << "Decryption succeeded with s = 1." << endl;
		success = true;
	}

	cout << "Decrypted message " << (message.equal(&decrypted_gp_minus_1) ? "matches" : "does not match") << " original" << endl;
	cout << "Decrypted message: " << endl << decrypted_gp_minus_1.toStr(ASCII) << endl;

	BN_CTX_free(ctx);
	bn_free_ptrs(&bn_ptrs);
}

void Set5Challenge36() {
	vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	ByteVector bigP = ByteVector("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", HEX);
	BIGNUM *N = bn_from_bytevector(&bigP, &bn_ptrs);
	BIGNUM *g = bn_from_word(2, &bn_ptrs);
	BIGNUM *k = bn_from_word(3, &bn_ptrs);

	char *email = "test@test.com";
	char *password = "password";
	SRPServer server = SRPServer(N, g, k, email, password);

	// generate private key
	BIGNUM *a = BN_new();
	bn_add_to_ptrs(a, &bn_ptrs);
	if (!BN_rand_range(a, N)) {
		cout << "Error generating client private key" << endl;
		bn_free_ptrs(&bn_ptrs);
		return;
	}

	// generate public key
	BIGNUM *A = BN_new();
	bn_add_to_ptrs(A, &bn_ptrs);
	if (!BN_mod_exp(A, g, a, N, ctx)) {
		cout << "Error generating client private key" << endl;
		bn_free_ptrs(&bn_ptrs);
		return;
	}

	// initial exchange - send I, A to server and recieve salt, B
	ByteVector emailBV = ByteVector(email, ASCII);
	ByteVector ABV = ByteVector();
	bn_to_bytevector(A, &ABV);
	SRP_message message;
	message.data = ByteVector(emailBV.length() + ABV.length());
	emailBV.copyBytesByIndex(&message.data, 0, emailBV.length(), 0);
	ABV.copyBytesByIndex(&message.data, 0, ABV.length(), emailBV.length());
	message.num_items = 2;
	message.first_item_len = emailBV.length();
	message.special = EXCHANGE_KEYS;
	cout << "Sending initial message to server..." << endl;
	SRP_message response1 = server.response(message);
	cout << "Response recieved from server" << endl;
	if (response1.special != EXCHANGE_KEYS || response1.num_items != 2 || response1.first_item_len == 0) {
		cout << "Unexpected response from server" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	// extract response info
	ByteVector saltBV = ByteVector(response1.first_item_len);
	response1.data.copyBytesByIndex(&saltBV, 0, response1.first_item_len, 0);
	ByteVector BBV = ByteVector(response1.data.length() - response1.first_item_len);
	response1.data.copyBytesByIndex(&BBV, response1.first_item_len, response1.data.length() - response1.first_item_len, 0);

	BIGNUM *B = bn_from_bytevector(&BBV, &bn_ptrs);

	// compute uH, u
	ByteVector hashIn = ByteVector();
	bv_concat(&ABV, &BBV, &hashIn);
	ByteVector uH = ByteVector();
	ByteEncryption::sha256(&hashIn, &uH);
	BIGNUM *u = bn_from_bytevector(&uH, &bn_ptrs);

	// generate xH and x
	ByteVector passwordBV = ByteVector(password, ASCII);
	ByteVector hashIn2 = ByteVector();
	bv_concat(&saltBV, &passwordBV, &hashIn2);
	ByteVector xH = ByteVector();
	ByteEncryption::sha256(&hashIn2, &xH);
	BIGNUM *x = bn_from_bytevector(&xH, &bn_ptrs);

	// generate S = (B - k * g**x)**(a + u * x) % N
	BIGNUM *S = BN_new();
	BIGNUM *temp = BN_new();
	BIGNUM *temp1 = BN_new();
	BIGNUM *temp2 = BN_new();
	bn_add_to_ptrs(S, &bn_ptrs);
	bn_add_to_ptrs(temp, &bn_ptrs);
	bn_add_to_ptrs(temp1, &bn_ptrs);
	bn_add_to_ptrs(temp2, &bn_ptrs);
	
	if (!BN_mod_exp(temp1, g, x, N, ctx)) {
		cout << "Error while generating client S" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	if (!BN_mod_mul(temp2, temp1, k, N, ctx)) {
		cout << "Error while generating client S" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	if (!BN_mod_sub(temp, B, temp2, N, ctx)) {
		cout << "Error while generating client S" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	if (!BN_mod_mul(temp1, u, x, N, ctx)) {
		cout << "Error while generating client S" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	if (!BN_mod_add(temp2, a, temp1, N, ctx)) {
		cout << "Error while generating client S" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	if (!BN_mod_exp(S, temp, temp2, N, ctx)) {
		cout << "Error while generating client S" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}

	// generate K
	ByteVector SBV = ByteVector();
	bn_to_bytevector(S, &SBV);
	ByteVector K = ByteVector();
	ByteEncryption::sha256(&SBV, &K);

	// generate HMAC(K,salt)
	ByteVector HMAC = ByteVector();
	ByteEncryption::sha256_HMAC(&saltBV, &K, &HMAC);

	// prepare message
	message.data.resize(HMAC.length());
	HMAC.copyBytesByIndex(&message.data, 0, HMAC.length(), 0);
	message.num_items = 1;
	message.first_item_len = HMAC.length();
	message.special = HMAC_VERIFY;
	cout << "Sending HMAC to server for validation..." << endl;
	SRP_message response2 = server.response(message);
	if (response2.special != OK) {
		cout << "HMAC validation not OK" << endl;
	}
	else {
		cout << "HMAC validation OK" << endl;
	}

	BN_CTX_free(ctx);
	bn_free_ptrs(&bn_ptrs);
}

void Set5Challenge37() {
	// Providing an A value equivalent to zero mod N (i.e. 0, N, N*x, N^x) means that the server will generate K = SHA256(0). 
	// HMAC-SHA256(SHA256(0),salt) can be sent by the client without needing to know the valid password.

	vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	ByteVector bigP = ByteVector("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", HEX);
	BIGNUM *N = bn_from_bytevector(&bigP, &bn_ptrs);
	BIGNUM *g = bn_from_word(2, &bn_ptrs);
	BIGNUM *k = bn_from_word(3, &bn_ptrs);

	char *email = "test@test.com";
	char *secretpassword = "password";
	SRPServer server = SRPServer(N, g, k, email, secretpassword);


	// A = 0
	BIGNUM *A = bn_from_word(0, &bn_ptrs);
	cout << "Attempting to authenticate by providing A = 0" << endl;
	ByteVector emailBV = ByteVector(email, ASCII);
	ByteVector ABV = ByteVector();
	bn_to_bytevector(A, &ABV);
	SRP_message message;
	message.data = ByteVector(emailBV.length() + ABV.length());
	emailBV.copyBytesByIndex(&message.data, 0, emailBV.length(), 0);
	ABV.copyBytesByIndex(&message.data, 0, ABV.length(), emailBV.length());
	message.num_items = 2;
	message.first_item_len = emailBV.length();
	message.special = EXCHANGE_KEYS;
	cout << "Sending initial message to server..." << endl;
	SRP_message response1 = server.response(message);
	cout << "Response recieved from server" << endl;
	if (response1.special != EXCHANGE_KEYS || response1.num_items != 2 || response1.first_item_len == 0) {
		cout << "Unexpected response from server" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	// extract response info
	ByteVector saltBV = ByteVector(response1.first_item_len);
	response1.data.copyBytesByIndex(&saltBV, 0, response1.first_item_len, 0);
	ByteVector BBV = ByteVector(response1.data.length() - response1.first_item_len);
	response1.data.copyBytesByIndex(&BBV, response1.first_item_len, response1.data.length() - response1.first_item_len, 0);


	cout << "Sending zero key HMAC." << endl;
	BIGNUM *zero = bn_from_word(0, &bn_ptrs);
	ByteVector zeroS = ByteVector(1); 
	bn_to_bytevector(zero, &zeroS);
	ByteVector zeroKey = ByteVector();
	ByteEncryption::sha256(&zeroS, &zeroKey);
	ByteVector zeroHMAC = ByteVector();
	ByteEncryption::sha256_HMAC(&saltBV, &zeroKey, &zeroHMAC);

	SRP_message message2;

	message2.data.resize(zeroHMAC.length());
	zeroHMAC.copyBytesByIndex(&message2.data, 0, zeroHMAC.length(), 0);
	message2.num_items = 1;
	message2.first_item_len = zeroHMAC.length();
	message2.special = HMAC_VERIFY;
	SRP_message response2 = server.response(message2);
	if (response2.special != OK) {
		cout << "HMAC validation not OK" << endl;
	}
	else {
		cout << "HMAC validation OK" << endl;
	}

	// A = N
	cout << endl << "Attempting to authenticate by providing A = N" << endl;
	if (BN_copy(A, N) == NULL) {
		cout << "Error while setting A" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	bn_to_bytevector(A, &ABV);
	message.data.resize(emailBV.length() + ABV.length());
	ABV.copyBytesByIndex(&message.data, 0, ABV.length(), emailBV.length());
	cout << "Sending initial message to server..." << endl;
	SRP_message response1N = server.response(message);
	cout << "Response recieved from server" << endl;
	if (response1N.special != EXCHANGE_KEYS || response1N.num_items != 2 || response1N.first_item_len == 0) {
		cout << "Unexpected response from server" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	cout << "Sending zero key HMAC." << endl;
	SRP_message response2N = server.response(message2);
	if (response2N.special != OK) {
		cout << "HMAC validation not OK" << endl;
	}
	else {
		cout << "HMAC validation OK" << endl;
	}

	// A = 2*N
	cout << endl << "Attempting to authenticate by providing A = 2*N" << endl;
	BIGNUM *two = bn_from_word(2, &bn_ptrs);
	if (!BN_mul(A, A, two, ctx)) {
		cout << "Error while multiplying A" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	bn_to_bytevector(A, &ABV);
	message.data.resize(emailBV.length() + ABV.length());
	ABV.copyBytesByIndex(&message.data, 0, ABV.length(), emailBV.length());
	cout << "Sending initial message to server..." << endl;
	SRP_message response1_2N = server.response(message);
	if (response1_2N.special != EXCHANGE_KEYS || response1_2N.num_items != 2 || response1_2N.first_item_len == 0) {
		cout << "Unexpected recieved from server" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	cout << "Sending zero key HMAC." << endl;
	SRP_message response2_2N = server.response(message2);
	if (response2_2N.special != OK) {
		cout << "HMAC validation not OK" << endl;
	}
	else {
		cout << "HMAC validation OK" << endl;
	}

	// A = N^2
	cout << endl << "Attempting to authenticate by providing A = N^2" << endl;
	if (!BN_mul(A, N, N, ctx)) {
		cout << "Error while multipying N" << endl;
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	bn_to_bytevector(A, &ABV);
	message.data.resize(emailBV.length() + ABV.length());
	ABV.copyBytesByIndex(&message.data, 0, ABV.length(), emailBV.length());
	cout << "Sending initial message to server..." << endl;
	SRP_message response1_N2 = server.response(message);
	if (response1_N2.special != EXCHANGE_KEYS || response1_N2.num_items != 2 || response1_N2.first_item_len == 0) {
		cout << "Unexpected response from server" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	cout << "Sending zero key HMAC." << endl;
	SRP_message response2_N2 = server.response(message2);
	if (response2_N2.special != OK) {
		cout << "HMAC validation not OK" << endl;
	}
	else {
		cout << "HMAC validation OK" << endl;
	}


	BN_CTX_free(ctx);
	bn_free_ptrs(&bn_ptrs);

}

void Set5Challenge38() {
	vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	// Part 1 - test simplified protocol
	cout << "Testing authentication with simplified SRP" << endl;
	ByteVector bigP = ByteVector("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", HEX);
	BIGNUM *N = bn_from_bytevector(&bigP, &bn_ptrs);
	BIGNUM *g = bn_from_word(2, &bn_ptrs);
	BIGNUM *k = bn_from_word(3, &bn_ptrs);

	char *email = "test@test.com";
	char *password = "password";
	SRPServer server = SRPServer(N, g, k, email, password, true, false); // simplified SRP protocol server

	// generate private key
	BIGNUM *a = BN_new();
	bn_add_to_ptrs(a, &bn_ptrs);
	if (!BN_rand_range(a, N)) {
		cout << "Error generating client private key" << endl;
		bn_free_ptrs(&bn_ptrs);
		return;
	}

	// generate public key
	BIGNUM *A = BN_new();
	bn_add_to_ptrs(A, &bn_ptrs);
	if (!BN_mod_exp(A, g, a, N, ctx)) {
		cout << "Error generating client private key" << endl;
		bn_free_ptrs(&bn_ptrs);
		return;
	}

	// initial exchange - send I, A to server and recieve salt, B, u
	ByteVector emailBV = ByteVector(email, ASCII);
	ByteVector ABV = ByteVector();
	bn_to_bytevector(A, &ABV);
	SRP_message message;
	message.data = ByteVector(emailBV.length() + ABV.length());
	emailBV.copyBytesByIndex(&message.data, 0, emailBV.length(), 0);
	ABV.copyBytesByIndex(&message.data, 0, ABV.length(), emailBV.length());
	message.num_items = 2;
	message.first_item_len = emailBV.length();
	message.special = EXCHANGE_KEYS;
	cout << "Sending initial message to server..." << endl;
	SRP_message response1 = server.response(message);
	cout << "Response recieved from server" << endl;
	if (response1.special != EXCHANGE_KEYS || response1.num_items != 3 || response1.first_item_len == 0 || response1.second_item_len == 0) {
		cout << "Unexpected response from server" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	// extract response info
	ByteVector saltBV = ByteVector(response1.first_item_len);
	response1.data.copyBytesByIndex(&saltBV, 0, response1.first_item_len, 0);
	ByteVector BBV = ByteVector(response1.second_item_len);
	response1.data.copyBytesByIndex(&BBV, response1.first_item_len, response1.second_item_len, 0);
	ByteVector uBV = ByteVector(response1.data.length() - response1.first_item_len - response1.second_item_len);
	response1.data.copyBytesByIndex(&uBV, response1.first_item_len + response1.second_item_len, uBV.length(), 0);

	BIGNUM *u = bn_from_bytevector(&uBV, &bn_ptrs);
	BIGNUM *B = bn_from_bytevector(&BBV, &bn_ptrs);

	// generate xH and x
	ByteVector passwordBV = ByteVector(password, ASCII);
	ByteVector hashIn2 = ByteVector();
	bv_concat(&saltBV, &passwordBV, &hashIn2);
	ByteVector xH = ByteVector();
	ByteEncryption::sha256(&hashIn2, &xH);
	BIGNUM *x = bn_from_bytevector(&xH, &bn_ptrs);

	// generate S = (B)**(a + u * x) % N
	BIGNUM *S = BN_new();
	BIGNUM *temp1 = BN_new();
	BIGNUM *temp2 = BN_new();
	bn_add_to_ptrs(S, &bn_ptrs);
	bn_add_to_ptrs(temp1, &bn_ptrs);
	bn_add_to_ptrs(temp2, &bn_ptrs);

	if (!BN_mod_mul(temp1, u, x, N, ctx)) {
		cout << "Error while generating client S" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	if (!BN_mod_add(temp2, a, temp1, N, ctx)) {
		cout << "Error while generating client S" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	if (!BN_mod_exp(S, B, temp2, N, ctx)) {
		cout << "Error while generating client S" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}

	// generate K
	ByteVector SBV = ByteVector();
	bn_to_bytevector(S, &SBV);
	ByteVector K = ByteVector();
	ByteEncryption::sha256(&SBV, &K);

	// generate HMAC(K,salt)
	ByteVector HMAC = ByteVector();
	ByteEncryption::sha256_HMAC(&saltBV, &K, &HMAC);

	// prepare message
	message.data.resize(HMAC.length());
	HMAC.copyBytesByIndex(&message.data, 0, HMAC.length(), 0);
	message.num_items = 1;
	message.first_item_len = HMAC.length();
	message.special = HMAC_VERIFY;
	cout << "Sending HMAC to server for validation..." << endl;
	SRP_message response2 = server.response(message);
	if (response2.special != OK) {
		cout << "HMAC validation not OK" << endl;
	}
	else {
		cout << "HMAC validation OK" << endl;
	}

	// Part 2 - MITM component
	cout << endl << "Testing password dictionary attack with MITM server" << endl;
	SRPServer mitmServer = SRPServer(N, g, k, email, password, true, true); // note that password and email are not stored on initialization for our MITM server.
	// as client, send I and A. I'm reusing these from the previous test server
	SRP_message mitm_message1;
	bv_concat(&emailBV, &ABV, &mitm_message1.data);
	mitm_message1.num_items = 2;
	mitm_message1.first_item_len = emailBV.length();
	mitm_message1.special = EXCHANGE_KEYS;
	cout << "Sending initial message to server..." << endl;
	SRP_message mitm_response1 = mitmServer.response(mitm_message1);
	cout << "Response recieved from server" << endl;
	if (mitm_response1.special != EXCHANGE_KEYS || mitm_response1.num_items != 3 || mitm_response1.first_item_len == 0 || mitm_response1.second_item_len == 0) {
		cout << "Unexpected response from server" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	// extract response info
	ByteVector mitm_saltBV = ByteVector(mitm_response1.first_item_len);
	mitm_response1.data.copyBytesByIndex(&mitm_saltBV, 0, mitm_response1.first_item_len, 0);
	ByteVector mitm_BBV = ByteVector(mitm_response1.second_item_len);
	mitm_response1.data.copyBytesByIndex(&mitm_BBV, mitm_response1.first_item_len, mitm_response1.second_item_len, 0);
	ByteVector mitm_uBV = ByteVector(mitm_response1.data.length() - mitm_response1.first_item_len - mitm_response1.second_item_len);
	mitm_response1.data.copyBytesByIndex(&mitm_uBV, mitm_response1.first_item_len + mitm_response1.second_item_len, mitm_uBV.length(), 0);

	BIGNUM *mitm_u = bn_from_bytevector(&mitm_uBV, &bn_ptrs);
	BIGNUM *mitm_B = bn_from_bytevector(&mitm_BBV, &bn_ptrs);

	// generate xH and x
	ByteVector mitm_hashIn2 = ByteVector();
	bv_concat(&mitm_saltBV, &passwordBV, &mitm_hashIn2);
	ByteVector mitm_xH = ByteVector();
	ByteEncryption::sha256(&mitm_hashIn2, &mitm_xH);
	BIGNUM *mitm_x = bn_from_bytevector(&mitm_xH, &bn_ptrs);

	// generate S = (B)**(a + u * x) % N
	BIGNUM *mitm_S = BN_new();
	bn_add_to_ptrs(mitm_S, &bn_ptrs);

	if (!BN_mod_mul(temp1, mitm_u, mitm_x, N, ctx)) {
		cout << "Error while generating client S" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	if (!BN_mod_add(temp2, a, temp1, N, ctx)) {
		cout << "Error while generating client S" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}
	if (!BN_mod_exp(mitm_S, mitm_B, temp2, N, ctx)) {
		cout << "Error while generating client S" << endl;
		BN_CTX_free(ctx);
		bn_free_ptrs(&bn_ptrs);
		return;
	}


	// generate K
	ByteVector mitm_SBV = ByteVector();
	bn_to_bytevector(mitm_S, &mitm_SBV);
	
	ByteVector mitm_K = ByteVector();
	ByteEncryption::sha256(&mitm_SBV, &mitm_K);

	// generate HMAC(K,salt)
	ByteVector mitm_HMAC = ByteVector();
	ByteEncryption::sha256_HMAC(&mitm_saltBV, &mitm_K, &mitm_HMAC);

	// prepare message
	SRP_message mitm_message2;
	mitm_message2.data.resize(mitm_HMAC.length());
	mitm_HMAC.copyBytesByIndex(&mitm_message2.data, 0, mitm_HMAC.length(), 0);
	mitm_message2.num_items = 1;
	mitm_message2.first_item_len = mitm_HMAC.length();
	mitm_message2.special = HMAC_VERIFY;
	cout << "Sending HMAC to server for validation..." << endl;
	SRP_message mitm_response2 = mitmServer.response(mitm_message2);

	if (mitm_response2.special != OK) {
		cout << "HMAC validation not OK" << endl;
	}
	else {
		cout << "HMAC validation OK" << endl;
	}

	// at this point if we were working with an actual MITM setup, we could pass the password to the actual server to validate, but I think the
	// principle has been demonstrated.

	BN_CTX_free(ctx);
	bn_free_ptrs(&bn_ptrs);
}

void Set5Challenge39() {
	
	// note that due to the simplistic method of converting messages to integers, for a message of
	// suitable length the encrypted value for two messages encrypted with different public keys
	// is identical and thus decryptable with different private keys.

	cout << "Testing RSA encryption with 512 bit primes (this may take a moment)" << endl;
	RSAClient client1 = RSAClient(512, false);

	ByteVector plain1 = ByteVector("This is a test message", ASCII);
	ByteVector encrypted1 = ByteVector();
	ByteVector decrypted1 = ByteVector();

	cout << "Plaintext: " << endl << plain1.toStr(ASCII) << endl;
	client1.encrypt_bv(&plain1, &encrypted1);
	cout << "Encrypted with public key" << endl;
	encrypted1.printHexStrByBlocks(16);
	client1.decrypt_bv(&encrypted1, &decrypted1);
	cout << "Decrypted with private key" << endl << decrypted1.toStr(ASCII) << endl;

	cout << "Testing RSA encryption with 1024 bit primes (this may take a moment)" << endl;
	RSAClient client2 = RSAClient(1024, false);

	ByteVector plain2 = ByteVector("This is another test message", ASCII);
	ByteVector encrypted2 = ByteVector();
	ByteVector decrypted2 = ByteVector();

	cout << "Plaintext: " << endl << plain2.toStr(ASCII) << endl;
	client2.encrypt_bv(&plain2, &encrypted2);
	cout << "Encrypted with public key" << endl;
	encrypted2.printHexStrByBlocks(16);
	client2.decrypt_bv(&encrypted2, &decrypted2);
	cout << "Decrypted with private key" << endl << decrypted2.toStr(ASCII) << endl;

}

void Set5Challenge40() {
	vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	// Generate 3 different sets of private and public keys
	cout << "Generating clients 1-3..." << endl;
	RSAClient client1 = RSAClient(128);
	RSAClient client2 = RSAClient(128);
	RSAClient client3 = RSAClient(128);

	ByteVector thesecretplaintext = ByteVector("This is a secret!", ASCII);

	// get public keys from each client
	BIGNUM *e1 = BN_new();
	BIGNUM *n1 = BN_new();
	BIGNUM *e2 = BN_new();
	BIGNUM *n2 = BN_new();
	BIGNUM *e3 = BN_new();
	BIGNUM *n3 = BN_new();
	bn_add_to_ptrs(e1, &bn_ptrs);
	bn_add_to_ptrs(n1, &bn_ptrs);
	bn_add_to_ptrs(e2, &bn_ptrs);
	bn_add_to_ptrs(n2, &bn_ptrs);
	bn_add_to_ptrs(e3, &bn_ptrs);
	bn_add_to_ptrs(n3, &bn_ptrs);
	client1.public_key(e1, n1);
	client2.public_key(e2, n2);
	client3.public_key(e3, n3);

	cout << "Generating ciphertexts 1-3..." << endl;
	// get each ciphertext
	ByteVector encrypted1 = ByteVector();
	ByteVector encrypted2 = ByteVector();
	ByteVector encrypted3 = ByteVector();
	client1.encrypt_bv(&thesecretplaintext, &encrypted1);
	client2.encrypt_bv(&thesecretplaintext, &encrypted2);
	client3.encrypt_bv(&thesecretplaintext, &encrypted3);
	BIGNUM *c1 = bn_from_bytevector(&encrypted1, &bn_ptrs);
	BIGNUM *c2 = bn_from_bytevector(&encrypted2, &bn_ptrs);
	BIGNUM *c3 = bn_from_bytevector(&encrypted3, &bn_ptrs);

	cout << "Attempting Hastad's broadcast attack..." << endl;
	// I can't believe this works
	BIGNUM *result = bn_from_word(0, &bn_ptrs);
	BIGNUM *temp = BN_new();
	BIGNUM *ms1 = BN_new();
	BIGNUM *ms2 = BN_new();
	BIGNUM *ms3 = BN_new();
	bn_add_to_ptrs(temp, &bn_ptrs);
	bn_add_to_ptrs(ms1, &bn_ptrs);
	bn_add_to_ptrs(ms2, &bn_ptrs);
	bn_add_to_ptrs(ms3, &bn_ptrs);
	// ms1 = n2 * n3, ms2 = n1*n3, ms3 = n1*n2
	if (!BN_mul(ms1, n2, n3, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mul(ms2, n1, n3, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mul(ms3, n1, n2, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}

	// result += c1 * (ms1) * invmod(ms1, n1)
	if (NULL == BN_mod_inverse(temp, ms1, n1, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mul(temp, temp, ms1, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mul(temp, temp, c1, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_add(result, result, temp)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}

	// result += c2 * (ms2) * invmod(ms2, n2)
	if (NULL == BN_mod_inverse(temp, ms2, n2, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mul(temp, temp, ms2, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mul(temp, temp, c2, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_add(result, result, temp)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}

	// result += c3 * (ms3) * invmod(ms3, n3)
	if (NULL == BN_mod_inverse(temp, ms3, n3, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mul(temp, temp, ms3, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mul(temp, temp, c3, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_add(result, result, temp)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}

	// N = n1 * n2 * n3
	BIGNUM *N = BN_new();
	bn_add_to_ptrs(N, &bn_ptrs);
	if (!BN_mul(N, n1, n2, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mul(N, N, n3, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}

	// A complaint about the description of the challenge at https://cryptopals.com/sets/5/challenges/40. At time of writing
	// the instructions indicate that this modulo step shouldn't be performed before taking the cube root of the result.

	// result = result % N
	if (!BN_mod(result, result, N, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}

	// get cube root of result
	BIGNUM *three = bn_from_word(3, &bn_ptrs);
	BIGNUM *cube_root = BN_new();
	bn_add_to_ptrs(cube_root, &bn_ptrs);
	if (!bn_nth_root(result, three, cube_root)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}

	cout << "Decrypted message: " << endl;
	ByteVector message = ByteVector();
	bn_to_bytevector(cube_root, &message);
	cout << message.toStr(ASCII) << endl;


	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
}

int Set5() {
	cout << "### SET 5 ###" << endl;
	cout << "Set 5 Challenge 33" << endl;
	Set5Challenge33();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 5 Challenge 34" << endl;
	Set5Challenge34();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 5 Challenge 35" << endl;
	Set5Challenge35();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 5 Challenge 36" << endl;
	Set5Challenge36();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 5 Challenge 37" << endl;
	Set5Challenge37();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 5 Challenge 38" << endl;
	Set5Challenge38();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 5 Challenge 39" << endl;
	Set5Challenge39();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 5 Challenge 40" << endl;
	Set5Challenge40();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	return 0;
}