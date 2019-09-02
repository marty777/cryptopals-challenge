#pragma once
#include "ByteVector.h"

// handles encryption/decryption operations using ByteVector objects

class ByteEncryptionError 
{
public:
	int err;
	std::string message;

	void clear();
	void print();
};

class ByteEncryption
{
public:
	ByteEncryption();
	~ByteEncryption();

	// pass false to encrypt to perform decryption.
	static void aes_ecb_encrypt_block(byte *input, byte *key, int keyLengthBytes, byte *output, bool encrypt);
	static void aes_ecb_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, size_t start_index, size_t end_index, bool encrypt);
	static void aes_cbc_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, ByteVector *iv, bool encrypt);

	static bool aes_random_encrypt(ByteVector *bv, ByteVector *output);
	static void aes_append_encrypt(ByteVector *bv, ByteVector *appendBv, ByteVector *key, ByteVector *output, bool verbose = false);
	static void aes_prepend_append_encrypt(ByteVector *prependBv, ByteVector *bv, ByteVector *appendBv, ByteVector *key, ByteVector *output, bool verbose = false, bool cbc = false, ByteVector *iv = NULL);

	static void challenge16encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, ByteVector *iv, bool verbose = false);
	static bool challenge16decrypt(ByteVector *bv, ByteVector *key, ByteVector *iv);

	static int aes_repeated_block_count(ByteVector *bv);
	static size_t aes_seq_repeated_block_count(ByteVector *bv);

	static void pkcs7Pad(ByteVector *bv, size_t block_size);
	static void pkcs7ForcePad(ByteVector *bv, size_t block_size, size_t start_len, size_t target_len);
	static void pkcs7Strip(ByteVector *bv, size_t block_size);
	static bool pkcs7PaddingValidate(ByteVector *bv, size_t block_size, ByteVector *output, ByteEncryptionError *err);
	static bool pkcs7PaddingValidate(ByteVector *bv, ByteVector *output, ByteEncryptionError *err);
};

