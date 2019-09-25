#pragma once
#include "ByteVector.h"

class ByteEncryptionAES {
	
	const ByteVector sbox = ByteVector(
		"637c777bf26b6fc53001672bfed7ab76"
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
	~ByteEncryptionAES();
	//void setKey(ByteVector *key);
	uint32_t *expandKey(ByteVector *key, uint32_t *keysize);
	int KeyNr(uint32_t keysize);
	int KeyNk(uint32_t keysize);
	void aes_encipher(ByteVector *input, uint32_t *expandedKey, uint32_t keysize, ByteVector *output);
	void shiftrows(ByteVector *b);
private:
	uint32_t subword(uint32_t word);
	void subbytes(ByteVector *b);

	void mixcolumns(ByteVector *b);
	// just the non-zero byte of RCON[i]
	byte rcon(int i);
	byte gmul(byte a, byte b);
	// xor each byte of state vector with byte from appropriate word starting at index w_i in w.
	void addRoundKey(ByteVector *state, uint32_t *w, size_t w_i);
};