#include "ByteEncryption.h"
#include <assert.h>
#include <openssl/aes.h>
#include <iostream>



int rand_range(int start, int end) {
	return start + (rand() % (1 + end - start));
}

ByteEncryption::ByteEncryption()
{
}


ByteEncryption::~ByteEncryption()
{
}

void ByteEncryption::aes_ecb_encrypt_block(byte *input, byte *key, int keyLengthBytes, byte *output, bool encrypt) {
	// setting up the wrapper this way adds extra steps by re-doing the aes key each block, but eh.
	AES_KEY aesKey;
	encrypt ? AES_set_encrypt_key(key, keyLengthBytes * 8, &aesKey) : AES_set_decrypt_key(key, keyLengthBytes * 8, &aesKey);
	AES_ecb_encrypt(input, output, &aesKey, encrypt ? AES_ENCRYPT : AES_DECRYPT);
}

// In the spirit of the challenge, I should probably implement the cipher directly, but I'm using OpenSSL for now
void ByteEncryption::aes_ecb_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, size_t start_index, size_t end_index, bool encrypt) {
	// test a few things
	// key length - 128, 192 or 256 bits
	assert(key->length() == 16 || key->length() == 24 || key->length() == 32);
	
	// check the bv has been padded to 16 bytes
	assert(bv->length() % 16 == 0);

	// check start and end indexes are 16-byte aligned within the bounds of the input vector, and the end index is >= the start index
	assert(start_index % 16 == 0 && (end_index + 1) % 16 == 0 && start_index < bv->length() && end_index < bv->length() && start_index <= end_index);

	// check the output vector matches the input vector in length
	assert(bv->length() == output->length());

	AES_KEY aesKey;
	if(encrypt) {
		AES_set_encrypt_key(key->dataPtr(), (int)key->length() * 8, &aesKey);
	}
	else {
		AES_set_decrypt_key(key->dataPtr(), (int)key->length() * 8, &aesKey);
	}

	for (size_t i = start_index; i < end_index; i += 16) {
		AES_ecb_encrypt(bv->dataPtr() + i, output->dataPtr() + i, &aesKey, encrypt ? AES_ENCRYPT : AES_DECRYPT);
	}
}


void ByteEncryption::aes_cbc_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, ByteVector *iv, bool encrypt) {
	// key length - 128, 192 or 256 bits
	assert(key->length() == 16 || key->length() == 24 || key->length() == 32);
	// check the bv has been padded to 16 bytes
	assert(bv->length() % 16 == 0);
	// check the output vector matches the input vector in length
	assert(bv->length() == output->length());
	// check the iv is 16 bytes
	assert(iv->length() == 16);
	
	ByteVector inputIv = ByteVector(iv);
	ByteVector inputBv = ByteVector(16);
	ByteVector outputBv = ByteVector(16);

	for (size_t i = 0; i < bv->length() ; i+=16) {
		if (encrypt) {
			// inputBv = inputIv ^ input block
			inputIv.copyBytes(&inputBv);
			inputBv.xorByIndex(bv, 0, 16, i);
			// encrypt block with key
			ByteEncryption::aes_ecb_encrypt_block(inputBv.dataPtr(), key->dataPtr(), key->length(), outputBv.dataPtr(), encrypt);
			// copy outputBv to output and inputIv
			outputBv.copyBytes(&inputIv);
			outputBv.copyBytesByIndex(output, 0, 16, i);
		}
		else {
			// inputBv = input block
			bv->copyBytesByIndex(&inputBv, i, 16, 0);
			// decrypt input block
			ByteEncryption::aes_ecb_encrypt_block(inputBv.dataPtr(), key->dataPtr(), (int)key->length(), outputBv.dataPtr(), encrypt);
			// output block = outputBv ^ inputIv
			outputBv.xorByIndex (&inputIv, 0, 16, 0);
			outputBv.copyBytesByIndex(output, 0, 16, i);
			// inputIv = input block
			bv->copyBytesByIndex(&inputIv, i, 16, 0);
		}
	}

}

bool ByteEncryption::aes_random_encrypt(ByteVector *bv, ByteVector *output) {

	// just going to use 128-bit keys for this test
	ByteVector key = ByteVector(16);
	key.random();

	// Perform random padding
	int prepadding = rand_range(5, 10);
	int postpadding = rand_range(5, 10);
	ByteVector input = ByteVector(bv->length() + prepadding + postpadding);
	for (size_t i = 0; i < prepadding; i++) {
		input.setAtIndex(0, i);
	}
	for (size_t i = 0; i < postpadding; i++) {
		input.setAtIndex(0, input.length() - 1 - i);
	}
	for (size_t i = 0; i < bv->length(); i++) {
		input.setAtIndex(bv->atIndex(i), prepadding + i);
	}

	// further pad to 16-byte blocksize
	if (input.length() % 16 != 0) {
		size_t old_len = input.length();
		size_t new_len = old_len + (16 - (input.length() % 16));
		input.resize(new_len);
		for (size_t i = old_len; i < new_len; i++) {
			input.setAtIndex(0, i);
		}
	}
	output->resize(input.length());


	bool mode = ((rand() % 2) == 0);
	if (mode) {
		// ECB
		ByteEncryption::aes_ecb_encrypt(&input, &key, output, 0, input.length() - 1, true);
	}
	else {
		// CBC
		ByteVector iv = ByteVector(16);
		iv.random();
		ByteEncryption::aes_cbc_encrypt(&input, &key, output, &iv, true);
	}

	// returning this for testing purposes.
	return mode;
}

// returns the number of 16-byte blocks in the vector that appear more than once
int ByteEncryption::aes_repeated_block_count(ByteVector *bv) {
	// probably smarter ways to do this, but eh
	int count = 0;
	for (size_t i = 0; i < bv->length(); i+=16) {
		for (size_t j = 0; j < bv->length(); j++) {
			if (j == i) {
				continue;
			}
			bool match = true;
			for (size_t k = 0; k < 16; k++) {
				if (bv->atIndex(i + k) != bv->atIndex(j + k)) {
					match = false;
					break;
				}
			}
			if (match) {
				count++;
				break;
			}
		}
	}
	return count;
}