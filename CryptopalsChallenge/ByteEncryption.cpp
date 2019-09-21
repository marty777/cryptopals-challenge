#include "ByteEncryption.h"
#include "KeyValueParser.h"
#include "ByteRandom.h"
#include <assert.h>
#include <openssl/aes.h>
#include <iostream>

void ByteEncryptionError::clear() {
	err = 0;
	message = "";
}
void ByteEncryptionError::print() {
	if (err != 0) {
		std::cout << "ByteEncryptionError:\t" << message.c_str() << "(" << err << ")" << std::endl;
	}
}

bool ByteEncryptionError::hasErr() {
	return (err != 0);
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
	assert(bv->length() % AES_BLOCK_SIZE == 0);

	// check start and end indexes are 16-byte aligned within the bounds of the input vector, and the end index is >= the start index
	assert(start_index % AES_BLOCK_SIZE == 0 && (end_index + 1) % AES_BLOCK_SIZE == 0 && start_index < bv->length() && end_index < bv->length() && start_index <= end_index);

	// check the output vector matches the input vector in length
	assert(bv->length() == output->length());

	AES_KEY aesKey;
	if(encrypt) {
		AES_set_encrypt_key(key->dataPtr(), (int)key->length() * 8, &aesKey);
	}
	else {
		AES_set_decrypt_key(key->dataPtr(), (int)key->length() * 8, &aesKey);
	}

	for (size_t i = start_index; i < end_index; i += AES_BLOCK_SIZE) {
		AES_ecb_encrypt(bv->dataPtr() + i, output->dataPtr() + i, &aesKey, encrypt ? AES_ENCRYPT : AES_DECRYPT);
	}
}


void ByteEncryption::aes_cbc_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, ByteVector *iv, bool encrypt) {
	// key length - 128, 192 or 256 bits
	assert(key->length() == 16 || key->length() == 24 || key->length() == 32);
	// check the bv has been padded to 16 bytes
	assert(bv->length() % AES_BLOCK_SIZE == 0);
	// check the output vector matches the input vector in length
	assert(bv->length() == output->length());
	// check the iv is 16 bytes
	assert(iv->length() == AES_BLOCK_SIZE);
	
	ByteVector inputIv = ByteVector(iv);
	ByteVector inputBv = ByteVector(AES_BLOCK_SIZE);
	ByteVector outputBv = ByteVector(AES_BLOCK_SIZE);

	
	for (size_t i = 0; i < bv->length() ; i+= AES_BLOCK_SIZE) {
		if (encrypt) {
			// inputBv = inputIv ^ input block
			inputIv.copyBytes(&inputBv);
			inputBv.xorByIndex(bv, 0, AES_BLOCK_SIZE, i);
			// encrypt block with key
			ByteEncryption::aes_ecb_encrypt_block(inputBv.dataPtr(), key->dataPtr(), key->length(), outputBv.dataPtr(), encrypt);
			// copy outputBv to output and inputIv
			outputBv.copyBytes(&inputIv);
			outputBv.copyBytesByIndex(output, 0, AES_BLOCK_SIZE, i);
		}
		else {
			// inputBv = input block
			bv->copyBytesByIndex(&inputBv, i, AES_BLOCK_SIZE, 0);
			// decrypt input block
			ByteEncryption::aes_ecb_encrypt_block(inputBv.dataPtr(), key->dataPtr(), (int)key->length(), outputBv.dataPtr(), encrypt);
			// output block = outputBv ^ inputIv
			outputBv.xorByIndex (&inputIv, 0, AES_BLOCK_SIZE, 0);
			outputBv.copyBytesByIndex(output, 0, AES_BLOCK_SIZE, i);
			// inputIv = input block
			bv->copyBytesByIndex(&inputIv, i, AES_BLOCK_SIZE, 0);
		}
	}

}

void ByteEncryption::aes_cbc_encrypt_check(ByteVector *bv, ByteVector *key, ByteVector *output, ByteVector *iv, bool encrypt) {
	// key length - 128, 192 or 256 bits
	assert(key->length() == 16 || key->length() == 24 || key->length() == 32);
	// check the bv has been padded to 16 bytes
	assert(bv->length() % AES_BLOCK_SIZE == 0);
	// check the output vector matches the input vector in length
	assert(bv->length() == output->length());
	// check the iv is 16 bytes
	assert(iv->length() == AES_BLOCK_SIZE);

	ByteVector inputIv = ByteVector(iv);

	AES_KEY aesKey;
	if (encrypt) {
		AES_set_encrypt_key(key->dataPtr(), (int)key->length() * 8, &aesKey);
	}
	else {
		AES_set_decrypt_key(key->dataPtr(), (int)key->length() * 8, &aesKey);
	}

	std::cout << "CBC Encrypt TEST " << (encrypt ? "encrypt" : "decrypt") << std::endl;
	std::cout << "Input: " << std::endl;
	bv->printHexStrByBlocks(16);
	std::cout << "IV: " << std::endl;
	iv->printHexStrByBlocks(16);
	std::cout << "inputIV: " << std::endl;
	inputIv.printHexStrByBlocks(16);

	AES_cbc_encrypt(bv->dataPtr(), output->dataPtr(), bv->length(), &aesKey, inputIv.dataPtr(), (encrypt ? AES_ENCRYPT : AES_DECRYPT ));

	std::cout << "Output: " << std::endl;
	output->printHexStrByBlocks(16);
}

// for challenge 11
bool ByteEncryption::aes_random_encrypt(ByteVector *bv, ByteVector *output) {

	// just going to use 128-bit keys for this test
	ByteVector key = ByteVector(16);
	key.random();

	// Perform random padding
	int prepadding = ByteRandom::rand_range(5, 10);
	int postpadding = ByteRandom::rand_range(5, 10);
	size_t inputlen = bv->length() + prepadding + postpadding;
	if (inputlen % 16 != 0) {
		inputlen += 16 - (inputlen % 16);
	}
	ByteVector input = ByteVector();
	input.reserve(inputlen); // includes space for padding
	input.resize(bv->length() + prepadding + postpadding);
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
	ByteEncryption::pkcs7Pad(&input, AES_BLOCK_SIZE);
	output->resize(input.length());


	bool mode = ((rand() % 2) == 0);
	if (mode) {
		// ECB
		ByteEncryption::aes_ecb_encrypt(&input, &key, output, 0, input.length() - 1, true);
	}
	else {
		// CBC
		ByteVector iv = ByteVector(AES_BLOCK_SIZE);
		iv.random();
		ByteEncryption::aes_cbc_encrypt(&input, &key, output, &iv, true);
	}

	// returning this for testing purposes.
	return mode;
}

// for challenge 12
void ByteEncryption::aes_append_encrypt(ByteVector *bv, ByteVector *appendBv, ByteVector *key, ByteVector *output, bool verbose) {
	// append appendVector to ciphertext, pad to 16 bytes and encypt in ECB mode with provided key
	size_t inputlen = bv->length() + appendBv->length();
	if (inputlen % 16 != 0) {
		inputlen += 16 - (inputlen % 16);
	}
	ByteVector input = ByteVector();
	input.reserve(inputlen); // reserve space for the padding
	input.resize(bv->length() + appendBv->length());
	
	for (size_t i = 0; i < bv->length(); i++) {
		input.setAtIndex(bv->atIndex(i), i);
	}
	for (size_t i = 0; i < appendBv->length(); i++) {
		input.setAtIndex(appendBv->atIndex(i), i + bv->length());
	}
	ByteEncryption::pkcs7Pad(&input, AES_BLOCK_SIZE);
	output->resize(inputlen);
	ByteEncryption::aes_ecb_encrypt(&input, key, output, 0, inputlen - 1, true);
	
	if (verbose) {
		std::cout << "Input breakdown:" << std::endl;
		for (int i = 0; i < inputlen / AES_BLOCK_SIZE; i++) {
			ByteVector inputBlock = ByteVector(AES_BLOCK_SIZE);
			input.copyBytesByIndex(&inputBlock, i * AES_BLOCK_SIZE, AES_BLOCK_SIZE, 0);
			std::cout << i << ":\t" << inputBlock.toStr(HEX) << std::endl;
		}
		std::cout << "Output breakdown:" << std::endl;
		for (int i = 0; i < inputlen / AES_BLOCK_SIZE; i++) {
			ByteVector outputBlock = ByteVector(AES_BLOCK_SIZE);
			output->copyBytesByIndex(&outputBlock, i * AES_BLOCK_SIZE, AES_BLOCK_SIZE, 0);
			std::cout << i << ":\t" << outputBlock.toStr(HEX) << std::endl;
		}
	}
}

// for challenge 14 - random count of random bytes + bv + appendBv, AES ECB encrypted
void ByteEncryption::aes_prepend_append_encrypt(ByteVector *prependBv, ByteVector *bv, ByteVector *appendBv, ByteVector *key, ByteVector *output, bool verbose, bool cbc, ByteVector *iv) {
	assert(!cbc || (cbc && iv != NULL));

	size_t inputlen = prependBv->length() + bv->length() + appendBv->length();
	if (inputlen % 16 != 0) {
		inputlen += 16 - (inputlen % 16);
	}
	ByteVector input = ByteVector();
	input.reserve(inputlen);
	input.resize(prependBv->length() + bv->length() + appendBv->length());

	for (size_t i = 0; i < prependBv->length(); i++) {
		input.setAtIndex(prependBv->atIndex(i), i);
	}
	for (size_t i = 0; i < bv->length(); i++) {
		input.setAtIndex(bv->atIndex(i), i + prependBv->length());
	}
	for (size_t i = 0; i < appendBv->length(); i++) {
		input.setAtIndex(appendBv->atIndex(i), i + prependBv->length() + bv->length());
	}
	
	ByteEncryption::pkcs7Pad(&input, AES_BLOCK_SIZE);
	output->resize(inputlen);
	if (cbc) {
		ByteEncryption::aes_cbc_encrypt(&input, key, output, iv, true);
	}
	else {
		ByteEncryption::aes_ecb_encrypt(&input, key, output, 0, inputlen - 1, true);
	}

	if (verbose) {
		std::cout << "Input breakdown:" << std::endl;
		for (int i = 0; i < inputlen / AES_BLOCK_SIZE; i++) {
			ByteVector inputBlock = ByteVector(AES_BLOCK_SIZE);
			input.copyBytesByIndex(&inputBlock, i * AES_BLOCK_SIZE, AES_BLOCK_SIZE, 0);
			std::cout << i << ":\t" << inputBlock.toStr(HEX) << std::endl;
		}
		std::cout << "Output breakdown:" << std::endl;
		for (int i = 0; i < inputlen / AES_BLOCK_SIZE; i++) {
			ByteVector outputBlock = ByteVector(AES_BLOCK_SIZE);
			output->copyBytesByIndex(&outputBlock, i * AES_BLOCK_SIZE, AES_BLOCK_SIZE, 0);
			std::cout << i << ":\t" << outputBlock.toStr(HEX) << std::endl;
		}
	}
}


void ByteEncryption::challenge16encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, ByteVector *iv, bool verbose) {
	ByteVector pre = ByteVector("comment1=cooking%20MCs;userdata=", ASCII);
	ByteVector post = ByteVector(";comment2=%20like%20a%20pound%20of%20bacon", ASCII);
	size_t input_len = 0;
	for (size_t i = 0; i < bv->length(); i++) {
		if (bv->atIndex(i) == ';' || bv->atIndex(i) == '=') {
			input_len += 3;
		}
		else {
			input_len++;
		}
	}
	ByteVector input = ByteVector();
	input.reserve(input_len);
	for (size_t i = 0; i < bv->length(); i++) {
		// urlencode our unsafe characters
		if (bv->atIndex(i) == ';') {
			input.append('%');
			input.append('3');
			input.append('B');
		}
		else if(bv->atIndex(i) == '=') {
			input.append('%');
			input.append('3');
			input.append('D');
		}
		else {
			input.append(bv->atIndex(i));
		}
	}
	ByteEncryption::aes_prepend_append_encrypt(&pre, &input, &post, key, output, false, true, iv);
}
bool ByteEncryption::challenge16decrypt(ByteVector *bv, ByteVector *key, ByteVector *iv) {
	ByteVector output = ByteVector(bv->length());
	ByteEncryption::aes_cbc_encrypt(bv, key, &output, iv, false);
	ByteVector stripped = ByteVector();
	ByteEncryptionError err;
	ByteEncryption::pkcs7PaddingValidate(&output, AES_BLOCK_SIZE, &stripped, &err);
	KeyValueParser parser = KeyValueParser();
	if (err.err > 0) {
		parser.parseDelimited(&output, ';', '=');
	}
	else {
		parser.parseDelimited(&stripped, ';', '=');
	}
	if (parser.valueWithKey("admin") == "true") {
		return true;
	}
	return false;
}

void ByteEncryption::challenge17encrypt(std::vector<ByteVector> *inputs, ByteVector *key, ByteVector *output, ByteVector *iv, bool verbose) {
	int inputIndex = ByteRandom::rand_range(0, inputs->size() - 1);
	ByteVector input = ByteVector(inputs->at((size_t)inputIndex));
	ByteEncryption::pkcs7Pad(&input, AES_BLOCK_SIZE);
	output->resize(input.length());
	ByteEncryption::aes_cbc_encrypt(&input, key, output, iv, true);
}

bool ByteEncryption::challenge17paddingvalidate(ByteVector *bv, ByteVector *key, ByteVector *iv) {
	ByteEncryptionError err = ByteEncryptionError();
	ByteVector output = ByteVector(bv->length());
	ByteEncryption::aes_cbc_encrypt(bv, key, &output, iv, false);
	ByteVector stripped = ByteVector();
	ByteEncryption::pkcs7PaddingValidate(&output, &stripped, &err);
	return !err.hasErr();
}


// returns the number of 16-byte blocks in the vector that appear more than once
int ByteEncryption::aes_repeated_block_count(ByteVector *bv) {
	// probably smarter ways to do this, but eh
	int count = 0;
	for (size_t i = 0; i < bv->length(); i+= AES_BLOCK_SIZE) {
		for (size_t j = 0; j < bv->length(); j++) {
			if (j == i) {
				continue;
			}
			bool match = true;
			for (size_t k = 0; k < AES_BLOCK_SIZE && i+k < bv->length() && j+k < bv->length(); k++) {
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

// returns the highest number of sequentially identical blocks in the vector
size_t ByteEncryption::aes_seq_repeated_block_count(ByteVector *bv) {
	size_t high_count = 0;
	size_t count = 0;
	for (size_t i = 0; i < bv->length() - AES_BLOCK_SIZE; i += AES_BLOCK_SIZE) {
		if (bv->equalAtIndex(bv, i, AES_BLOCK_SIZE, i + AES_BLOCK_SIZE)) {
			count++;
		}
		else {
			if (count > 0 && count > high_count) {
				high_count = count;
			}
			count = 0;
		}
	}
	if (count > high_count) {
		high_count = count;
	}
	return high_count;
}


void ByteEncryption::pkcs7Pad(ByteVector *bv, size_t block_size) {
	assert(block_size < 0x100);
	size_t init_len = bv->length();
	if (bv->length() % block_size != 0) {
		
		bv->resize(init_len + (block_size - (bv->length() % block_size)));
		byte b = (byte)(bv->length() - init_len);
		for (size_t i = init_len; i < bv->length(); i++) {
			bv->setAtIndex(b, i);
		}
	}
	else {
		byte b = (byte)block_size;
		bv->resize(init_len + block_size);
		for (size_t i = init_len; i < bv->length(); i++) {
			bv->setAtIndex(b, i);
		}
	}
}

// regardless of length of bv, treat it as start_len bytes long and pad to target_len
void ByteEncryption::pkcs7ForcePad(ByteVector *bv, size_t block_size, size_t start_len, size_t target_len) {
	assert(block_size < 0x100);
	assert(target_len >= start_len);
	assert((target_len - start_len) < 0x100);
	assert(target_len % block_size == 0);
	assert(start_len < bv->length());
	if (bv->length() != target_len) {
		bv->resize(target_len);
	}
	byte b = (byte)(target_len - start_len);
	for (size_t i = start_len; i < target_len; i++) {
		bv->setAtIndex(b, i);
	}
}

// validate and strip PKCS#7 padding.
// Returns true if validation passed. If validation fails, output will not be updated and err will be.
bool ByteEncryption::pkcs7PaddingValidate(ByteVector *bv, size_t block_size, ByteVector *output, ByteEncryptionError *err) {
	
	if (block_size < 2 || block_size >= 256) {
		err->err = 1;
		err->message = "Invalid block size";
		return false;
	}

	if (bv->length() == 0 || bv->length() % block_size != 0) {
		err->err = 2;
		err->message = "Input not padded to block size";
		return false;
	}

	byte final = bv->atIndex(bv->length() - 1);
	if (final == 0) {
		err->err = 3;
		err->message = "Invalid padding byte found";
		return false;
	}
	for (size_t j = 0; j < final; j++) {
		if (bv->atIndex(bv->length() - 1 - j) != final) {
			err->err = 3;
			err->message = "Invalid padding byte found";
			return false;
		}
	}

	output->resize(bv->length() - (size_t)final);
	bv->copyBytesByIndex(output, 0, output->length(), 0);
	return true;
}

bool ByteEncryption::pkcs7PaddingValidate(ByteVector *bv, ByteVector *output, ByteEncryptionError *err) {
	return ByteEncryption::pkcs7PaddingValidate(bv, AES_BLOCK_SIZE, output, err);
}

// load nonce and counter into output block (16 bytes) as
// 64 bit unsigned little endian nonce, 64 bit little endian block count
void ByteEncryption::ctr_generate_counter(unsigned long long nonce, unsigned long long count, ByteVector *output) {
	assert(output->length() == AES_BLOCK_SIZE);
	for (int i = 0; i < 8; i++) {
		byte n = (byte)(0xff & (nonce >> i*8));
		byte c = (byte)(0xff & (count >> i*8));
		output->setAtIndex(n, i);
		output->setAtIndex(c, 8 + i);
	}
}

// might modify this to take a function pointer if we're likely to switch counter methods
// note that we don't switch behaviour between encryption and decryption
// May want this to allow random access, it's a stream cipher after all.
void ByteEncryption::aes_ctr_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, unsigned long long nonce) {
	// key length - 128, 192 or 256 bits
	assert(key->length() == 16 || key->length() == 24 || key->length() == 32);
	// check input and output are same length
	assert(bv->length() == output->length());
	
	ByteVector ctr = ByteVector(AES_BLOCK_SIZE);
	ByteVector enciphered = ByteVector(AES_BLOCK_SIZE);
	unsigned long long count = 0;
	size_t index = 0;
	while (index < bv->length()) {
		ByteEncryption::ctr_generate_counter(nonce, count, &ctr);
		ByteEncryption::aes_ecb_encrypt(&ctr, key, &enciphered, 0, AES_BLOCK_SIZE-1, true);
		count++;
		
		for (size_t i = index; i < index + AES_BLOCK_SIZE && i < bv->length(); i++) {
			output->setAtIndex(bv->atIndex(i) ^ enciphered.atIndex(i % AES_BLOCK_SIZE), i);
		}
		index += AES_BLOCK_SIZE;
	}
}

// overwrite bv with CTR encrypted newBytes using key and nonce at specified offset
void ByteEncryption::aes_ctr_edit(ByteVector *bv, ByteVector *key, unsigned long long nonce, size_t offset, ByteVector *newBytes) {
	assert(offset + newBytes->length() <= bv->length());
	
	ByteVector ctr = ByteVector(AES_BLOCK_SIZE);
	ByteVector enciphered = ByteVector(AES_BLOCK_SIZE);

	size_t index = AES_BLOCK_SIZE * (offset / AES_BLOCK_SIZE);
	size_t count = (offset / AES_BLOCK_SIZE);

	while (index < offset + newBytes->length()) {
		ByteEncryption::ctr_generate_counter(nonce, count, &ctr);
		ByteEncryption::aes_ecb_encrypt(&ctr, key, &enciphered, 0, AES_BLOCK_SIZE - 1, true);
		count++;

		for (size_t i = index; i < index + AES_BLOCK_SIZE && i < bv->length(); i++) {
			if(i >= offset && i < offset+newBytes->length()) {
				bv->setAtIndex(newBytes->atIndex(i-offset) ^ enciphered.atIndex(i % AES_BLOCK_SIZE), i);
			}
		}
		index += AES_BLOCK_SIZE;
	}
}

// encrypts/decrypts input vector by XORing with keystream produced by MT19937 mersenne twister and writing to output vector
void ByteEncryption::mt19937_stream_encrypt(ByteVector *bv, uint16_t seed, ByteVector *output) {
	assert(bv->length() == output->length());

	ByteRandom random = ByteRandom();
	random.m_seed(seed);
	ByteVector keyStream = ByteVector(4);
	for (size_t i = 0; i < bv->length(); i++) {
		if (i % 4 == 0) {
			// convert a 32 bit value from the twister into 4 bytes in the keyStream vector
			ByteRandom::uint32_to_ByteVector(random.m_rand(), &keyStream);
		}
		output->setAtIndex(bv->atIndex(i) ^ keyStream.atIndex(i % 4) , i);
	}
}