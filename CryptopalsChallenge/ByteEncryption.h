#pragma once
#include "ByteVector.h"
// handles encryption/decryption operations using ByteVector objects

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
	static bool aes_append_encrypt(ByteVector *bv, ByteVector *appendBv, ByteVector *key, ByteVector *output, bool verbose = false);

	static int aes_repeated_block_count(ByteVector *bv);

	
};

