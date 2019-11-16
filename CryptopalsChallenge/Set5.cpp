#include "Set5.h"
#include "ByteVector.h"
#include "ByteEncryption.h"
#include "Utility.h"
#include <iostream>
#include "openssl\bn.h"
#include "BNUtility.h"
#include <vector>
#include <assert.h>
#include "SRPServer.h"

using namespace std;



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
	SRPServer server = SRPServer(bigP, 2, 3, email, password);

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
	SRP_message response1 = server.response(message);


	BN_CTX_free(ctx);
	bn_free_ptrs(&bn_ptrs);

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
}