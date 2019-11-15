#include "ByteEncryption.h"
#include "ByteEncryptionAES.h"
#include "KeyValueParser.h"
#include "ByteRandom.h"
#include "Utility.h"
#include <assert.h>
#include <iostream>
#include "BNUtility.h"

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

void ByteEncryption::aes_ecb_encrypt_block(byte *input, byte *key, size_t keylengthbytes, byte *output, bool encrypt) {

	ByteVector k = ByteVector(16);
	ByteVector in = ByteVector(16);
	ByteVector out = ByteVector(16);
	for (size_t i = 0; i < 16; i++) {
		in[i] = input[i];
		k[i] = key[i];
	}
	ByteEncryptionAES aes = ByteEncryptionAES();
	ByteEncryptionAESExpandedKey expandedKey;
	aes.expandKey(&k, &expandedKey);
	
	if (encrypt) {
		aes.aes_encipher(&in, &expandedKey, &out);
	}
	else {
		aes.aes_decipher(&in, &expandedKey, &out);
	}

	free(expandedKey.w);

	for (size_t i = 0; i < 16; i++) {
		output[i] = out[i];
	}
}

void ByteEncryption::aes_ecb_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, size_t start_index, size_t end_index, bool encrypt) {
	// key length - 128, 192 or 256 bits
	assert(key->length() == 16 || key->length() == 24 || key->length() == 32);
	// check the bv has been padded to 16 bytes
	assert(bv->length() % AES_BLOCK_SIZE == 0);
	// check start and end indexes are 16-byte aligned within the bounds of the input vector, and the end index is >= the start index
	assert(start_index % AES_BLOCK_SIZE == 0 && (end_index + 1) % AES_BLOCK_SIZE == 0 && start_index < bv->length() && end_index < bv->length() && start_index <= end_index);
	// check the output vector matches the input vector in length
	assert(bv->length() == output->length());

	ByteEncryptionAES aes = ByteEncryptionAES();
	ByteEncryptionAESExpandedKey expandedKey;
	aes.expandKey(key, &expandedKey);
	ByteVector in = ByteVector(16);
	ByteVector out = ByteVector(16);
	for (size_t i = start_index; i < end_index; i += AES_BLOCK_SIZE) {
		
		bv->copyBytesByIndex(&in, i, AES_BLOCK_SIZE, 0);
		if (encrypt) {
			aes.aes_encipher(&in, &expandedKey, &out);
		}
		else {
			aes.aes_decipher(&in, &expandedKey, &out);
		}
		out.copyBytesByIndex(output, 0, AES_BLOCK_SIZE, i);
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

// for challenge 11
bool ByteEncryption::aes_random_encrypt(ByteVector *bv, ByteVector *output) {

	// just going to use 128-bit keys for this test
	ByteVector key = ByteVector(16);
	key.random();

	// Perform random padding
	int prepadding = rand_range(5, 10);
	int postpadding = rand_range(5, 10);
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
	output->resize(input.length());
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
	if (inputlen % AES_BLOCK_SIZE != 0) {
		inputlen += AES_BLOCK_SIZE - (inputlen % AES_BLOCK_SIZE);
	}
	else {
		inputlen += AES_BLOCK_SIZE;
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

	output->resize(input.length());
	if (cbc) {
		ByteEncryption::aes_cbc_encrypt(&input, key, output, iv, true);
	}
	else {
		ByteEncryption::aes_ecb_encrypt(&input, key, output, 0, input.length() - 1, true);
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
	int inputIndex = rand_range(0, (int)inputs->size() - 1);
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


void ByteEncryption::challenge26encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, unsigned long long nonce) {
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
	input_len += pre.length();
	input_len += post.length();
	ByteVector input = ByteVector();
	input.reserve(input_len);
	for (size_t i = 0; i < pre.length(); i++) {
		input.append(pre.atIndex(i));
	}
	for(size_t i = 0; i < bv->length(); i++) {
		// urlencode our unsafe characters
		if (bv->atIndex(i) == ';') {
			input.append('%');
			input.append('3');
			input.append('B');
		}
		else if (bv->atIndex(i) == '=') {
			input.append('%');
			input.append('3');
			input.append('D');
		}
		else {
			input.append(bv->atIndex(i));
		}
	}
	for (size_t i = 0; i < post.length(); i++) {
		input.append(post.atIndex(i));
	}
	output->resize(input.length());
	ByteEncryption::aes_ctr_encrypt(&input, key, output, nonce);
}
bool ByteEncryption::challenge26decrypt(ByteVector *bv, ByteVector *key, unsigned long long nonce) {
	ByteVector output = ByteVector(bv->length());
	ByteEncryption::aes_ctr_encrypt(bv, key, &output, nonce);
	KeyValueParser parser = KeyValueParser();
	parser.parseDelimited(&output, ';', '=');
	
	if (parser.valueWithKey("admin") == "true") {
		return true;
	}
	return false;
}


void ByteEncryption::challenge27encrypt(ByteVector *bv, ByteVector *key, ByteVector *output) {
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
		else if (bv->atIndex(i) == '=') {
			input.append('%');
			input.append('3');
			input.append('D');
		}
		else {
			input.append(bv->atIndex(i));
		}
	}
	ByteEncryption::aes_prepend_append_encrypt(&pre, &input, &post, key, output, false, true, key);
}
bool ByteEncryption::challenge27decrypt(ByteVector *bv, ByteVector *key, ByteEncryptionError *err) {
	ByteVector output = ByteVector(bv->length());
	ByteEncryption::aes_cbc_encrypt(bv, key, &output, key, false);
	// check for high-ASCII first before padding validation
	bool high_ascii_present = false;
	for (size_t i = 0; i < output.length(); i++) {
		if (output.atIndex(i) > 127) {
			high_ascii_present = true;
			break;
		}
	}
	if (high_ascii_present || true) {
		err->err = 1;
		err->message = std::string("Noncompliant values: ") + std::string((output.toStr(ASCII)));
		return false;
	}
	ByteVector stripped = ByteVector();
	ByteEncryption::pkcs7PaddingValidate(&output, AES_BLOCK_SIZE, &stripped, err);
	if (err->hasErr()) {
		return false;
	}
	return true;
}

// returns false on error
bool ByteEncryption::challenge34Encrypt(BIGNUM *field_prime, BIGNUM *public_key, BIGNUM *private_key, ByteVector *message, ByteVector *output) {
	// obtain session key s given field_prime, partner's public_key and own private_key. Hash s using SHA1 and use first 16 bytes as key to encrypt message with AES-CBC with a random IV. IV is appended to encrypted message
	// before sending.
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *s = BN_new();
	if (!BN_mod_exp(s, public_key, private_key, field_prime, ctx)) {
		BN_CTX_free(ctx);
		BN_free(s);
		return false;
	}
	ByteVector sessionKey = ByteVector();
	bn_to_bytevector(s, &sessionKey);
	ByteVector sessionKeyHash = ByteVector();
	ByteEncryption::sha1(&sessionKey, &sessionKeyHash);

	ByteVector iv = ByteVector(16);
	iv.random();

	ByteVector aesKey = ByteVector(16);
	sessionKeyHash.copyBytesByIndex(&aesKey, 0, 16, 0);

	ByteVector paddedMessage = ByteVector(message);
	ByteEncryption::pkcs7Pad(&paddedMessage, AES_BLOCK_SIZE);

	ByteVector initialOutput = ByteVector(paddedMessage.length());
	ByteEncryption::aes_cbc_encrypt(&paddedMessage, &aesKey, &initialOutput, &iv, true);

	// copy initialOutput to output and append iv
	output->resize(initialOutput.length() + 16);
	initialOutput.copyBytesByIndex(output, 0, initialOutput.length(), 0);
	iv.copyBytesByIndex(output, 0, 16, initialOutput.length());

	BN_CTX_free(ctx);
	BN_free(s);

	return true;
}

// returns false on error
bool ByteEncryption::challenge34Decrypt(BIGNUM *field_prime, BIGNUM *public_key, BIGNUM *private_key, ByteVector *message, ByteVector *output) {
	// obtain session key s given field_prime, partner's public_key and own private_key. Hash s using SHA1 and use first 16 bytes as key to decrypt message with AES-CBC with IV appended to last 16 bytes of message
	// before sending.
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *s = BN_new();
	if (!BN_mod_exp(s, public_key, private_key, field_prime, ctx)) {
		BN_CTX_free(ctx);
		BN_free(s);
		return false;
	}
	ByteVector sessionKey = ByteVector();
	bn_to_bytevector(s, &sessionKey);
	ByteVector sessionKeyHash = ByteVector();
	ByteEncryption::sha1(&sessionKey, &sessionKeyHash);

	BN_CTX_free(ctx);
	BN_free(s);

	// copy last 16 bytes of message to iv
	ByteVector iv = ByteVector(16);
	message->copyBytesByIndex(&iv, message->length() - 16, 16, 0);

	ByteVector aesKey = ByteVector(16);
	sessionKeyHash.copyBytesByIndex(&aesKey, 0, 16, 0);

	// encrypted message is message less the final 16 bytes
	ByteVector truncatedMessage = ByteVector(message->length() - 16);
	message->copyBytesByIndex(&truncatedMessage, 0, message->length() - 16, 0);


	ByteVector paddedMessage = ByteVector(truncatedMessage.length());
	ByteEncryption::aes_cbc_encrypt(&truncatedMessage, &aesKey, &paddedMessage, &iv, false);
	ByteEncryptionError err = ByteEncryptionError();
	ByteEncryption::pkcs7PaddingValidate(&paddedMessage, output, &err);
	if (err.hasErr()) {
		return false;
	}
	return true;
}


bool ByteEncryption::challenge35Decrypt(BIGNUM *field_prime, BIGNUM *session_key, ByteVector *message, ByteVector *output) {
	ByteVector sessionKey = ByteVector();
	bn_to_bytevector(session_key, &sessionKey);
	ByteVector sessionKeyHash = ByteVector();
	ByteEncryption::sha1(&sessionKey, &sessionKeyHash);

	// copy last 16 bytes of message to iv
	ByteVector iv = ByteVector(16);
	message->copyBytesByIndex(&iv, message->length() - 16, 16, 0);

	ByteVector aesKey = ByteVector(16);
	sessionKeyHash.copyBytesByIndex(&aesKey, 0, 16, 0);

	// encrypted message is message less the final 16 bytes
	ByteVector truncatedMessage = ByteVector(message->length() - 16);
	message->copyBytesByIndex(&truncatedMessage, 0, message->length() - 16, 0);


	ByteVector paddedMessage = ByteVector(truncatedMessage.length());
	ByteEncryption::aes_cbc_encrypt(&truncatedMessage, &aesKey, &paddedMessage, &iv, false);
	ByteEncryptionError err = ByteEncryptionError();
	ByteEncryption::pkcs7PaddingValidate(&paddedMessage, output, &err);
	if (err.hasErr()) {
		return false;
	}
	return true;
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

// based on pseudocode from https://en.wikipedia.org/wiki/SHA-1
// length_offset (in bytes) can be passed to increment the final length bytes if forging an appended hash
void ByteEncryption::sha1(ByteVector *bv, ByteVector *output, size_t length_offset, uint32_t state0, uint32_t state1, uint32_t state2, uint32_t state3, uint32_t state4) {

	uint32_t h0 = state0;
	uint32_t h1 = state1;
	uint32_t h2 = state2;
	uint32_t h3 = state3;
	uint32_t h4 = state4;

	size_t m1 = (bv->length()) * 8;
	size_t m2 = (bv->length() + 1) * 8; // length in bits including 0x80 padding byte
	size_t message_len = m2 + ((512 - m2 % 512));
	if ((m2 % 512) > 448) {
		message_len += 512;
	}

	ByteVector message = ByteVector(message_len/8);
	message.allBytes(0);
	bv->copyBytesByIndex(&message, 0, bv->length(), 0);
	message[bv->length()] = 0x80;
	for (size_t i = 0; i < 8; i++) {
		// addition of length_offset for forging hash of appended messages
		byte len_chunk = (byte)(0xff) & ((m1 + (length_offset*8)) >> 8 * (8 - 1 - i));
		message[(message_len/8) - 8 + i] = len_chunk;
	}

	size_t message_chunk_index = 0;
	for (size_t i = 0; i < message_len/8; i += 64) {
		uint32_t w[80];
		for (size_t j = 0; j < 80; j++) {
			w[j] = 0;
		}
		// break chunk into 16 initial 32-bit words
		for (size_t j = 0; j < 16; j++) {
			w[j] = (((uint32_t)message[i + (4 * j) + 0]) << 24) | (((uint32_t)message[i + (4 * j) + 1]) << 16) | (((uint32_t)message[i + (4 * j) + 2]) << 8) | message[i + (4 * j) + 3];
		}

		// next 64 32-bit words are produced as:
		for (size_t j = 16; j < 80; j++) {
			w[j] = int32rotateleft((w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]), 1);
		}
		// initialize hash value for chunk
		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;
		uint32_t e = h4;

		for (size_t n = 0; n < 80; n++) {
			size_t f = 0;
			size_t k = 0;
			if (n >= 0 && n <= 19) {
				f = (b & c) | ((~b) & d);
				k = 0x5A827999;
			}
			else if (n >= 20 && n <= 39) {
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			}
			else if (n >= 40 && n <= 59) {
				f = (b & c) | (b & d) | (c & d);
				k = 0x8F1BBCDC;
			}
			else if (n >= 60 && n <= 79) {
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}

			uint32_t temp = int32rotateleft(a, 5) + (uint32_t)f + e + (uint32_t)k + w[n];
			e = d;
			d = c;
			c = int32rotateleft(b, 30);
			b = a;
			a = temp;
		}
		h0 = h0 + a;
		h1 = h1 + b;
		h2 = h2 + c;
		h3 = h3 + d;
		h4 = h4 + e;
	}

	//ByteVector output = ByteVector(20); // 160 bits
	output->resize(20);
	(*output)[0] = (byte)(h0 >> 24) & 0xff;
	(*output)[1] = (byte)(h0 >> 16) & 0xff;
	(*output)[2] = (byte)(h0 >> 8) & 0xff;
	(*output)[3] = (byte)(h0) & 0xff;
	(*output)[4] = (byte)(h1 >> 24) & 0xff;
	(*output)[5] = (byte)(h1 >> 16) & 0xff;
	(*output)[6] = (byte)(h1 >> 8) & 0xff;
	(*output)[7] = (byte)(h1) & 0xff;
	(*output)[8] = (byte)(h2 >> 24) & 0xff;
	(*output)[9] = (byte)(h2 >> 16) & 0xff;
	(*output)[10] = (byte)(h2 >> 8) & 0xff;
	(*output)[11] = (byte)(h2) & 0xff;
	(*output)[12] = (byte)(h3 >> 24) & 0xff;
	(*output)[13] = (byte)(h3 >> 16) & 0xff;
	(*output)[14] = (byte)(h3 >> 8) & 0xff;
	(*output)[15] = (byte)(h3) & 0xff;
	(*output)[16] = (byte)(h4 >> 24) & 0xff;
	(*output)[17] = (byte)(h4 >> 16) & 0xff;
	(*output)[18] = (byte)(h4 >> 8) & 0xff;
	(*output)[19] = (byte)(h4) & 0xff;
}

// MAC is SHA1( key CONCAT message ) 
void ByteEncryption::sha1_MAC(ByteVector *bv, ByteVector *key, ByteVector *output) {
	ByteVector input = ByteVector(key->length() + bv->length());
	key->copyBytesByIndex(&input, 0, bv->length(), 0);
	bv->copyBytesByIndex(&input, 0, bv->length(), key->length());

	ByteEncryption::sha1(&input, output);
}

// implementation based on pseudocode from https://en.wikipedia.org/wiki/SHA-2
void ByteEncryption::sha256(ByteVector *bv, ByteVector *output, size_t length_offset, uint32_t state0, uint32_t state1, uint32_t state2, uint32_t state3, uint32_t state4, uint32_t state5, uint32_t state6, uint32_t state7) {
	uint32_t h0 = state0;
	uint32_t h1 = state1;
	uint32_t h2 = state2;
	uint32_t h3 = state3;
	uint32_t h4 = state4;
	uint32_t h5 = state5;
	uint32_t h6 = state6; 
	uint32_t h7 = state7;

	uint32_t k[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	// pad input
	ByteVector input = ByteVector();
	size_t initial_len_bits = bv->length() * 8;
	size_t len = bv->length() + 9;
	len += 64 - (len % 64);
	input.resize(len);
	bv->copyBytesByIndex(&input, 0, bv->length(), 0);
	input[bv->length()] = 0x80;
	for (size_t i = bv->length() + 1; i < len - 8; i++) {
		input[i] = 0;
	}
	input[len - 8] = 0xff & (initial_len_bits >> 56);
	input[len - 7] = 0xff & (initial_len_bits >> 48);
	input[len - 6] = 0xff & (initial_len_bits >> 40);
	input[len - 5] = 0xff & (initial_len_bits >> 32);
	input[len - 4] = 0xff & (initial_len_bits >> 24);
	input[len - 3] = 0xff & (initial_len_bits >> 16);
	input[len - 2] = 0xff & (initial_len_bits >> 8);
	input[len - 1] = 0xff & (initial_len_bits);

	for (size_t i = 0; i < input.length(); i += 64) {
		// for each 512 bit chunk of the padded input

		// message schedule array 
		uint32_t w[64];
		for (size_t j = 0; j < 16; j++) {
			w[j] = (input[i + (4 * j)] << 24) | (input[i + (4 * j) + 1] << 16) | (input[i + (4 * j) + 2] << 8) | (input[i + (4 * j) + 3]);
		}
		for (size_t j = 16; j < 64; j++) {
			uint32_t s0 = int32rotateright(w[j - 15], 7) ^ int32rotateright(w[j - 15], 18) ^ (w[j - 15] >> 3);  //(w[j-15] rightrotate  7) xor (w[j-15] rightrotate 18) xor (w[j-15] rightshift  3)
			uint32_t s1 = int32rotateright(w[j - 2], 17) ^ int32rotateright(w[j - 2], 19) ^ (w[j - 2] >> 10);	//(w[j- 2] rightrotate 17) xor (w[j- 2] rightrotate 19) xor (w[j- 2] rightshift 10)
			w[j] = w[j - 16] + s0 + w[j - 7] + s1;
		}

		// internal variables
		uint32_t a, b, c, d, e, f, g, h;
		a = h0;
		b = h1;
		c = h2;
		d = h3;
		e = h4;
		f = h5;
		g = h6;
		h = h7;

		// compression function loop
		for (size_t j = 0; j < 64; j++) {
			uint32_t S1 = int32rotateright(e, 6) ^ int32rotateright(e, 11) ^ int32rotateright(e, 25);	//(e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
			uint32_t ch = (e & f) ^ ((~e) & g);															//(e and f) xor ((not e) and g)
			uint32_t temp1 = h + S1 + ch + k[j] + w[j];
			uint32_t S0 = int32rotateright(a, 2) ^ int32rotateright(a, 13) ^ int32rotateright(a, 22);	//(a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
			uint32_t maj = (a & b) ^ (a & c) ^ (b & c);													//(a and b) xor (a and c) xor (b and c);
			uint32_t temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	}

	output->resize(32);
	(*output)[0] = 0xff & (h0 >> 24);
	(*output)[1] = 0xff & (h0 >> 16);
	(*output)[2] = 0xff & (h0 >> 8);
	(*output)[3] = 0xff & (h0);
	(*output)[4] = 0xff & (h1 >> 24);
	(*output)[5] = 0xff & (h1 >> 16);
	(*output)[6] = 0xff & (h1 >> 8);
	(*output)[7] = 0xff & (h1);
	(*output)[8] = 0xff & (h2 >> 24);
	(*output)[9] = 0xff & (h2 >> 16);
	(*output)[10] = 0xff & (h2 >> 8);
	(*output)[11] = 0xff & (h2);
	(*output)[12] = 0xff & (h3 >> 24);
	(*output)[13] = 0xff & (h3 >> 16);
	(*output)[14] = 0xff & (h3 >> 8);
	(*output)[15] = 0xff & (h3);
	(*output)[16] = 0xff & (h4 >> 24);
	(*output)[17] = 0xff & (h4 >> 16);
	(*output)[18] = 0xff & (h4 >> 8);
	(*output)[19] = 0xff & (h4);
	(*output)[20] = 0xff & (h5 >> 24);
	(*output)[21] = 0xff & (h5 >> 16);
	(*output)[22] = 0xff & (h5 >> 8);
	(*output)[23] = 0xff & (h5);
	(*output)[24] = 0xff & (h6 >> 24);
	(*output)[25] = 0xff & (h6 >> 16);
	(*output)[26] = 0xff & (h6 >> 8);
	(*output)[27] = 0xff & (h6);
	(*output)[28] = 0xff & (h7 >> 24);
	(*output)[29] = 0xff & (h7 >> 16);
	(*output)[30] = 0xff & (h7 >> 8);
	(*output)[31] = 0xff & (h7);

}

uint32_t md4_F(uint32_t a, uint32_t b, uint32_t c) {
	return ((a&b) | ((~a)&c));
}
uint32_t md4_G(uint32_t a, uint32_t b, uint32_t c) {
	return ((a&b) | (a&c) | (b&c));
}
uint32_t md4_H(uint32_t a, uint32_t b, uint32_t c) {
	return (a ^ b ^ c);
}

void md4_round1(uint32_t *a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s) {
	(*a) = (*a) + md4_F(b, c, d) + x;
	(*a) = int32rotateleft((*a), s);
}

void md4_round2(uint32_t *a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s) {
	(*a) = (*a) + md4_G(b, c, d) + x + (uint32_t)0x5A827999;//0x9979825A; 
	(*a) = int32rotateleft((*a), s);
}

void md4_round3(uint32_t *a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s) {
	(*a) = (*a) + md4_H(b, c, d) + x + (uint32_t)0x6ED9EBA1; //0xA1EBD96E;
	(*a) = int32rotateleft((*a), s);
}


// Note: The spec for RFC 1320 uses least significant bytes first hence all the endian changes
void ByteEncryption::md4(ByteVector *bv, ByteVector *output, size_t length_offset, uint32_t state0, uint32_t state1, uint32_t state2, uint32_t state3) {
	uint32_t h0 = state0;
	uint32_t h1 = state1;
	uint32_t h2 = state2;
	uint32_t h3 = state3;

	// padding and length bytes identical to sha1
	size_t m1 = (bv->length()) * 8;
	size_t m2 = (bv->length() + 1) * 8; // length in bits including 0x80 padding byte
	size_t message_len = m2 + ((512 - m2 % 512));
	if ((m2 % 512) > 448) {
		message_len += 512;
	}

	ByteVector message = ByteVector(message_len / 8);
	message.allBytes(0);
	bv->copyBytesByIndex(&message, 0, bv->length(), 0);
	message[bv->length()] = 0x80;
	for (size_t i = 0; i < 8; i++) {
		// addition of length_offset for forging hash of appended messages
		byte len_chunk = (byte)(0xff) & ((m1 + (length_offset * 8)) >> 8 * (8 - 1 - i));
		message[(message_len / 8) - 8 + i] = len_chunk;
	}
	
	uint32_t x[16];
	uint32_t h0_temp, h1_temp, h2_temp, h3_temp;

	for (size_t i = 0; i < message_len / 8; i += 64) {
		for (size_t j = 0; j < 16; j++) {
			x[j] = (message[i + 4*j] << 24) | (message[1 + i + (4 * j)] << 16) | (message[2 + i + (4 * j)] << 8) | (message[3 + i + (4 * j)]);
			x[j] = int32reverseBytes(x[j]);
		}
		if (i == message_len / 8 - 64) {
			uint32_t temp = x[15];
			x[15] = int32reverseBytes( x[14] );
			x[14] = int32reverseBytes(temp);
		}

		h0_temp = h0;
		h1_temp = h1;
		h2_temp = h2;
		h3_temp = h3;

		// round 1
		md4_round1(&h0, h1, h2, h3, x[0], 3);
		md4_round1(&h3, h0, h1, h2, x[1], 7);
		md4_round1(&h2, h3, h0, h1, x[2], 11);
		md4_round1(&h1, h2, h3, h0, x[3], 19);
		md4_round1(&h0, h1, h2, h3, x[4], 3);
		md4_round1(&h3, h0, h1, h2, x[5], 7);
		md4_round1(&h2, h3, h0, h1, x[6], 11);
		md4_round1(&h1, h2, h3, h0, x[7], 19);
		md4_round1(&h0, h1, h2, h3, x[8], 3);
		md4_round1(&h3, h0, h1, h2, x[9], 7);
		md4_round1(&h2, h3, h0, h1, x[10], 11);
		md4_round1(&h1, h2, h3, h0, x[11], 19);
		md4_round1(&h0, h1, h2, h3, x[12], 3);
		md4_round1(&h3, h0, h1, h2, x[13], 7);
		md4_round1(&h2, h3, h0, h1, x[14], 11);
		md4_round1(&h1, h2, h3, h0, x[15], 19);

		// round 2
		md4_round2(&h0, h1, h2, h3, x[0], 3);
		md4_round2(&h3, h0, h1, h2, x[4], 5);
		md4_round2(&h2, h3, h0, h1, x[8], 9);
		md4_round2(&h1, h2, h3, h0, x[12], 13);
		md4_round2(&h0, h1, h2, h3, x[1], 3);
		md4_round2(&h3, h0, h1, h2, x[5], 5);
		md4_round2(&h2, h3, h0, h1, x[9], 9);
		md4_round2(&h1, h2, h3, h0, x[13], 13);
		md4_round2(&h0, h1, h2, h3, x[2], 3);
		md4_round2(&h3, h0, h1, h2, x[6], 5);
		md4_round2(&h2, h3, h0, h1, x[10], 9);
		md4_round2(&h1, h2, h3, h0, x[14], 13);
		md4_round2(&h0, h1, h2, h3, x[3], 3);
		md4_round2(&h3, h0, h1, h2, x[7], 5);
		md4_round2(&h2, h3, h0, h1, x[11], 9);
		md4_round2(&h1, h2, h3, h0, x[15], 13);


		// round 3
		md4_round3(&h0, h1, h2, h3, x[0], 3);
		md4_round3(&h3, h0, h1, h2, x[8], 9);
		md4_round3(&h2, h3, h0, h1, x[4], 11);
		md4_round3(&h1, h2, h3, h0, x[12], 15);
		md4_round3(&h0, h1, h2, h3, x[2], 3);
		md4_round3(&h3, h0, h1, h2, x[10], 9);
		md4_round3(&h2, h3, h0, h1, x[6], 11);
		md4_round3(&h1, h2, h3, h0, x[14], 15);
		md4_round3(&h0, h1, h2, h3, x[1], 3);
		md4_round3(&h3, h0, h1, h2, x[9], 9);
		md4_round3(&h2, h3, h0, h1, x[5], 11);
		md4_round3(&h1, h2, h3, h0, x[13], 15);
		md4_round3(&h0, h1, h2, h3, x[3], 3);
		md4_round3(&h3, h0, h1, h2, x[11], 9);
		md4_round3(&h2, h3, h0, h1, x[7], 11);
		md4_round3(&h1, h2, h3, h0, x[15], 15);

		h0 += h0_temp;
		h1 += h1_temp;
		h2 += h2_temp;
		h3 += h3_temp;
	}

	h0 = int32reverseBytes(h0);
	h1 = int32reverseBytes(h1);
	h2 = int32reverseBytes(h2);
	h3 = int32reverseBytes(h3);


	output->resize(16);
	(*output)[0] = (byte)(h0 >> 24) & 0xff;
	(*output)[1] = (byte)(h0 >> 16) & 0xff;
	(*output)[2] = (byte)(h0 >> 8) & 0xff;
	(*output)[3] = (byte)(h0) & 0xff;
	(*output)[4] = (byte)(h1 >> 24) & 0xff;
	(*output)[5] = (byte)(h1 >> 16) & 0xff;
	(*output)[6] = (byte)(h1 >> 8) & 0xff;
	(*output)[7] = (byte)(h1) & 0xff;
	(*output)[8] = (byte)(h2 >> 24) & 0xff;
	(*output)[9] = (byte)(h2 >> 16) & 0xff;
	(*output)[10] = (byte)(h2 >> 8) & 0xff;
	(*output)[11] = (byte)(h2) & 0xff;
	(*output)[12] = (byte)(h3 >> 24) & 0xff;
	(*output)[13] = (byte)(h3 >> 16) & 0xff;
	(*output)[14] = (byte)(h3 >> 8) & 0xff;
	(*output)[15] = (byte)(h3) & 0xff;

}

void ByteEncryption::md4_MAC(ByteVector *bv, ByteVector *key, ByteVector *output) {
	ByteVector input = ByteVector(key->length() + bv->length());
	key->copyBytesByIndex(&input, 0, bv->length(), 0);
	bv->copyBytesByIndex(&input, 0, bv->length(), key->length());

	ByteEncryption::md4(&input, output);
}