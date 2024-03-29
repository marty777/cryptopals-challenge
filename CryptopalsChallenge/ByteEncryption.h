#pragma once
#include "ByteVector.h"
#include <vector>
#include <openssl\bn.h>

class ByteEncryptionError 
{
public:
	int err;
	std::string message;

	void clear();
	void print();
	bool hasErr();
};

// handles encryption/decryption operations using ByteVector objects

class ByteEncryption
{
public:
	ByteEncryption();
	~ByteEncryption();

	// pass false to encrypt to perform decryption.
	static void aes_ecb_encrypt_block(byte *input, byte *key, size_t keyLengthBytes, byte *output, bool encrypt);
	static void aes_ecb_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, size_t start_index, size_t end_index, bool encrypt);
	static void aes_cbc_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, ByteVector *iv, bool encrypt);

	static bool aes_random_encrypt(ByteVector *bv, ByteVector *output);
	static void aes_append_encrypt(ByteVector *bv, ByteVector *appendBv, ByteVector *key, ByteVector *output, bool verbose = false);
	static void aes_prepend_append_encrypt(ByteVector *prependBv, ByteVector *bv, ByteVector *appendBv, ByteVector *key, ByteVector *output, bool verbose = false, bool cbc = false, ByteVector *iv = NULL);

	static void challenge16encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, ByteVector *iv, bool verbose = false);
	static bool challenge16decrypt(ByteVector *bv, ByteVector *key, ByteVector *iv);

	static void challenge17encrypt(std::vector<ByteVector> *inputs, ByteVector *key, ByteVector *output, ByteVector *iv, bool verbose = false);
	static bool challenge17paddingvalidate(ByteVector *bv, ByteVector *key, ByteVector *iv);

	static void challenge26encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, unsigned long long nonce);
	static bool challenge26decrypt(ByteVector *bv, ByteVector *key, unsigned long long nonce);

	static void challenge27encrypt(ByteVector *bv, ByteVector *key, ByteVector *output);
	static bool challenge27decrypt(ByteVector *bv, ByteVector *key, ByteEncryptionError *err);

	static bool challenge34Encrypt(BIGNUM *field_prime, BIGNUM *public_key, BIGNUM *private_key, ByteVector *message, ByteVector *output);
	static bool challenge34Decrypt(BIGNUM *field_prime, BIGNUM *public_key, BIGNUM *private_key, ByteVector *message, ByteVector *output);

	static bool challenge35Decrypt(BIGNUM *field_prime, BIGNUM *session_key, ByteVector *message, ByteVector *output);

	static int aes_repeated_block_count(ByteVector *bv);
	static size_t aes_seq_repeated_block_count(ByteVector *bv);

	static void pkcs7Pad(ByteVector *bv, size_t block_size);
	static void pkcs7ForcePad(ByteVector *bv, size_t block_size, size_t start_len, size_t target_len);
	static bool pkcs7PaddingValidate(ByteVector *bv, size_t block_size, ByteVector *output, ByteEncryptionError *err);
	static bool pkcs7PaddingValidate(ByteVector *bv, ByteVector *output, ByteEncryptionError *err);

	static void ctr_generate_counter(unsigned long long nonce, unsigned long long count, ByteVector *output);
	static void aes_ctr_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, unsigned long long nonce);
	static void aes_ctr_edit(ByteVector *bv, ByteVector *key, unsigned long long nonce, size_t offset, ByteVector *newBytes);

	static void mt19937_stream_encrypt(ByteVector *bv, uint16_t seed, ByteVector *output);

	static void sha1(ByteVector *bv, ByteVector *output, size_t length_offset = 0, uint32_t state0 = 0x67452301, uint32_t state1 = 0xEFCDAB89, uint32_t state2 = 0x98BADCFE, uint32_t state3 = 0x10325476, uint32_t state4 = 0xC3D2E1F0);
	static void sha1_MAC(ByteVector *bv, ByteVector *key, ByteVector *output);

	static void sha256(ByteVector *bv, ByteVector *output, size_t length_offset = 0, uint32_t state0 = 0x6a09e667, uint32_t state1 = 0xbb67ae85, uint32_t state2 = 0x3c6ef372, uint32_t state3 = 0xa54ff53a, uint32_t state4 = 0x510e527f, uint32_t state5 = 0x9b05688c, uint32_t state6 = 0x1f83d9ab, uint32_t state7 = 0x5be0cd19);
	static void sha256_HMAC(ByteVector *bv, ByteVector *key, ByteVector *output);

	static void md4(ByteVector *bv, ByteVector *output, size_t length_offset = 0, uint32_t state0 = 0x67452301, uint32_t state1 = 0xEFCDAB89, uint32_t state2 = 0x98BADCFE, uint32_t state3 = 0x10325476);
	static void md4_MAC(ByteVector *bv, ByteVector *key, ByteVector *output);
};

