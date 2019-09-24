#pragma once
#include "ByteVector.h"
#include <vector>

class ByteEncryptionAES {
	uint32_t *w;
	size_t keysize;
	const ByteVector sbox = ByteVector("637c777bf26b6fc53001672bfed7ab76"
		"ca82c97dfa5947f0add4a2af9ca472c0"
		"b7fd9326363ff7cc34a5e5f171d83115"
		"04c723c31896059a071280e2eb27b275"
		"09832c1a1b6e5aa0523bd6b329e32f84"
		"53d100ed20fcb15b6acbbe394a4c58cf"
		"d0efaafb434d338545f9027f503c9fa8"
		"51a3408f929d38f5bcb6da2110fff3d2"
		"cd0c13ec5f974417c4a77e3d645d1973"
		"60814fdc222a908846eeb814de5e0bdb"
		"e0323a0a4906245cc2d3ac629195e479"
		"e7c8376d8dd54ea96c56f4ea657aae08"
		"ba78252e1ca6b4c6e8dd741f4bbd8b8a"
		"703eb5664803f60e613557b986c11d9e"
		"e1f8981169d98e949b1e87e9ce5528df"
		"8ca1890dbfe6426841992d0fb054bb16", HEX);

public:
	ByteEncryptionAES();
	ByteEncryptionAES(ByteVector *key);
	~ByteEncryptionAES();
	void setKey(ByteVector *key);
	int KeyNr();
	int KeyNk();
	void aes_encipher(ByteVector *input, ByteVector *output);
	void shiftrows(ByteVector *b);
private:
	uint32_t subword(uint32_t word);
	void subbytes(ByteVector *b);
	
	void mixcolumns(ByteVector *b);
	// just the non-zero byte of RCON[i]
	byte rcon(int i);
	byte gmul(byte a, byte b);
	// xor each byte of state vector with byte from appropriate word starting at index w_i in w.
	void addRoundKey(ByteVector *state, size_t w_i);
};

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

	static void aes_ecb_encrypt_block2(byte *input, byte *key, int keyLengthBytes, byte *output, bool encrypt);
	// pass false to encrypt to perform decryption.
	static void aes_ecb_encrypt_block(byte *input, byte *key, int keyLengthBytes, byte *output, bool encrypt);
	static void aes_ecb_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, size_t start_index, size_t end_index, bool encrypt);
	static void aes_cbc_encrypt(ByteVector *bv, ByteVector *key, ByteVector *output, ByteVector *iv, bool encrypt);
	static void aes_cbc_encrypt_check(ByteVector *bv, ByteVector *key, ByteVector *output, ByteVector *iv, bool encrypt);

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

	static void sha1(ByteVector *bv, ByteVector *output, uint32_t state0 = 0x67452301, uint32_t state1 = 0xEFCDAB89, uint32_t state2 = 0x98BADCFE, uint32_t state3 = 0x10325476, uint32_t state4 = 0xC3D2E1F0);
	static void sha1_MAC(ByteVector *bv, ByteVector *key, ByteVector *output);
};

