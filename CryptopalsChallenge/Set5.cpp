#include "Set5.h"
#include "ByteVector.h"
#include "ByteEncryption.h"
#include "Utility.h"
#include <iostream>
#include "openssl\bn.h"
#include "BNUtility.h"

using namespace std;

void Set5Challenge33() {

	BN_CTX *ctx = BN_CTX_new();
	// initial test parameters
	BIGNUM *p1 = bn_from_word(37);
	BIGNUM *g1 = bn_from_word(5);
	// random integer 0 <= a1 < 37
	BIGNUM *a1 = BN_new();
	if (!BN_rand_range(a1, p1)) {
		cout << "Error encountered" << endl;
		return;
	}
	BIGNUM *A1 = BN_new();
	if (!BN_mod_exp(A1, g1, a1, p1, ctx)) {
		cout << "Error encountered" << endl;
		return;
	}
	// random integer 0 <= b1 < 37
	BIGNUM *b1 = BN_new();
	if (!BN_rand_range(b1, p1)) {
		cout << "Error encountered" << endl;
		return;
	}
	BIGNUM *B1 = BN_new();
	if (!BN_mod_exp(B1, g1, b1, p1, ctx)) {
		cout << "Error encountered" << endl;
		return;
	}

	BIGNUM *sA = BN_new();
	if (!BN_mod_exp(sA, B1, a1, p1, ctx)) {
		cout << "Error encountered" << endl;
		return;
	}
	BIGNUM *sB = BN_new();
	if (!BN_mod_exp(sA, A1, b1, p1, ctx)) {
		cout << "Error encountered" << endl;
		return;
	}

	if (!BN_cmp(sA, sB) == 0) {
		cout << "Small test of (A**b) % p equal to (B**a) % p" << endl;
	}
	else {
		cout << "Small test of (A**b) % p not equal to (B**a) % p" << endl;
	}

	BN_free(p1);
	BN_free(g1);
	BN_free(a1);
	BN_free(b1);
	BN_free(A1);
	BN_free(B1);
	BN_free(sA);
	BN_free(sB);

	// NIST parameters
	ByteVector bigP = ByteVector("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", HEX);
	BIGNUM *p = bn_from_bytevector(&bigP);
	BIGNUM *g = bn_from_word(2);
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *A = BN_new();
	BIGNUM *B = BN_new();
	if (!BN_rand_range(a, p)) {
		cout << "Error encountered" << endl;
		return;
	}
	if (!BN_rand_range(b, p)) {
		cout << "Error encountered" << endl;
		return;
	}
	if (!BN_mod_exp(A, g, a, p, ctx)) {
		cout << "Error encountered" << endl;
		return;
	}
	if (!BN_mod_exp(B, g, b, p, ctx)) {
		cout << "Error encountered" << endl;
		return;
	}
	BIGNUM *s1 = BN_new();
	if (!BN_mod_exp(s1, A, b, p, ctx)) {
		cout << "Error encountered" << endl;
		return;
	}
	BIGNUM *s2 = BN_new();
	if (!BN_mod_exp(s2, B, a, p, ctx)) {
		cout << "Error encountered" << endl;
		return;
	}
	if (!BN_cmp(sA, sB) == 0) {
		cout << "Large test of (A**b) % p equal to (B**a) % p" << endl;
	}
	else {
		cout << "Large test of (A**b) % p not equal to (B**a) % p" << endl;
	}
	
	BN_CTX_free(ctx);
	BN_free(p);
	BN_free(g);
	BN_free(a);
	BN_free(b);
	BN_free(A);
	BN_free(B);
	BN_free(s1);
	BN_free(s2);
}

void Set5Challenge34() {

	BN_CTX *ctx = BN_CTX_new();

	// field prime and generator parameters
	ByteVector bigP = ByteVector("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", HEX);
	BIGNUM *p = bn_from_bytevector(&bigP);
	BIGNUM *g = bn_from_word(2);

	// participants A and B
	BIGNUM *a_private_key = BN_new();
	BIGNUM *a_public_key = BN_new();
	if (!BN_rand_range(a_private_key, p)) {
		cout << "Error encountered" << endl;
		return;
	}
	if (!BN_mod_exp(a_public_key, g, a_private_key, p, ctx)) {
		cout << "Error encountered" << endl;
		return;
	}
	BIGNUM *b_private_key = BN_new();
	BIGNUM *b_public_key = BN_new();
	if (!BN_rand_range(b_private_key, p)) {
		cout << "Error encountered" << endl;
		return;
	}
	if (!BN_mod_exp(b_public_key, g, b_private_key, p, ctx)) {
		cout << "Error encountered" << endl;
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
	BIGNUM *m_cheat_private_key = bn_from_word(1);
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
}