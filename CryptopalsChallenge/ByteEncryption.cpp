#include "ByteEncryption.h"
#include <assert.h>
#include <openssl/aes.h>
#include <iostream>


ByteEncryption::ByteEncryption()
{
}


ByteEncryption::~ByteEncryption()
{
}

void ByteEncryption::aes_ecp_encrypt_block(byte *input, byte *key, int keyLengthBytes, byte *output, bool encrypt) {
	// setting up the wrapper this way adds extra steps byte re-doing the aes key each block, but eh.
	AES_KEY aesKey;
	encrypt ? AES_set_encrypt_key(key, keyLengthBytes * 8, &aesKey) : AES_set_decrypt_key(key, keyLengthBytes * 8, &aesKey);
	AES_ecb_encrypt(input, output, &aesKey, encrypt ? AES_ENCRYPT : AES_DECRYPT);
}

// In the spirit of the challenge, I should probably implement the cipher directly, but I'm using OpenSSL for now
void ByteEncryption::aes_ecb_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, size_t start_index, size_t end_index, bool encrypt) {
	// test a few things
	// key length - 128, 192 or 256 bits
	assert(key->length() != 16 && key->length() != 24 && key->length() != 32);
	
	// check the bv has been padded to 16 bytes
	assert(bv->length() % 16 == 0);

	// check start and end indexes are 16-byte aligned within the bounds of the input vector, and the end index is >= the start index
	assert(start_index % 16 == 0 && end_index % 16 == 0 && start_index < bv->length() && end_index < bv->length() && start_index <= end_index);

	// check the output vector matches the input vector in length
	assert(bv->length() == output->length());

	AES_KEY aesKey;
	if(encrypt) {
		AES_set_encrypt_key(key->dataPtr(), key->length() * 8, &aesKey);
	}
	else {
		AES_set_decrypt_key(key->dataPtr(), key->length() * 8, &aesKey);
	}

	for (int i = start_index; i < end_index; i += 16) {
		AES_ecb_encrypt(bv->dataPtr() + i, output->dataPtr() + i, &aesKey, encrypt ? AES_ENCRYPT : AES_DECRYPT);
	}
}


void ByteEncryption::aes_cbc_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, ByteVector *iv, bool encrypt) {
	// key length - 128, 192 or 256 bits
	//assert(key->length() != 16 && key->length() != 24 && key->length() != 32);
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
			ByteEncryption::aes_ecp_encrypt_block(inputBv.dataPtr(), key->dataPtr(), key->length(), outputBv.dataPtr(), encrypt);
			// copy outputBv to output and inputIv
			outputBv.copyBytes(&inputIv);
			outputBv.copyBytesByIndex(output, 0, 16, i);
		}
		else {
			// inputBv = input block
			bv->copyBytesByIndex(&inputBv, i, 16, 0);
			// decrypt input block
			ByteEncryption::aes_ecp_encrypt_block(inputBv.dataPtr(), key->dataPtr(), key->length(), outputBv.dataPtr(), encrypt);
			// output block = outputBv ^ inputIv
			outputBv.xorByIndex (&inputIv, 0, 16, 0);
			outputBv.copyBytesByIndex(output, 0, 16, i);
			// inputIv = input block
			bv->copyBytesByIndex(&inputIv, i, 16, 0);
		}
	}

}
