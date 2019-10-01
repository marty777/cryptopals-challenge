#include "ByteEncryptionAES.h"
#include "Utility.h"
#include <assert.h>
#include <iostream>

ByteEncryptionAES::ByteEncryptionAES() {
}

ByteEncryptionAES::~ByteEncryptionAES() {
}

void ByteEncryptionAES::expandKey(ByteVector *key, ByteEncryptionAESExpandedKey *expandedKey) {
	assert(key->length() == 16 || key->length() == 24 || key->length() == 32);
	uint32_t temp;
	// AES 128 - nk = 4, nr = 10
	// AES 192 - nk = 6, nr = 12
	// AES 256 - nk = 8, nr = 14
	expandedKey->keysize = (uint32_t)key->length();
	size_t nk = key->length() / 4;
	size_t nb = 4;
	size_t nr = nk + 6;
	
	

	expandedKey->w = (uint32_t *)malloc(sizeof(uint32_t) * nb * (nr + 1));

	for (size_t i = 0; i < nk; i++) {
		expandedKey->w[i] = ((*key)[4 * i] << 24) | ((*key)[4 * i + 1] << 16) | ((*key)[4 * i + 2] << 8) | ((*key)[4 * i + 3]);
	}
	for (size_t i = nb; i < nb*(nr + 1); i++) {
		temp = expandedKey->w[i - 1];
		if (i % nk == 0) {
			temp = subword(int32rotateleft(temp, 8)) ^ ((uint32_t)rcon((int)(i / nk)) << 24);
		}
		else if (nk > 6 && i % nk == 4) { // AES 256 modification to expansion
			temp = subword(temp);
		}
		expandedKey->w[i] = expandedKey->w[i - nk] ^ temp;
	}
}

int ByteEncryptionAES::KeyNr(uint32_t keysize) {
	return (keysize / 4) + 6;
}
int ByteEncryptionAES::KeyNk(uint32_t keysize) {
	return (keysize / 4);
}

void ByteEncryptionAES::aes_encipher(ByteVector *input, ByteEncryptionAESExpandedKey *key, ByteVector *output) {
	ByteVector state = ByteVector(16);
	for (size_t i = 0; i < state.length(); i++) {
		state[i] = (*input)[i];
	}

	int nr = this->KeyNr(key->keysize);
	int nb = 4;
	int nk = this->KeyNk(key->keysize);

	addRoundKey(&state, key->w, 0);

	for (int round = 1; round < nr; round++) {
		subbytes(&state);
		shiftrows(&state);
		mixcolumns(&state);
		addRoundKey(&state, key->w, round * nb);
	}

	subbytes(&state);
	shiftrows(&state);
	addRoundKey(&state, key->w, nr *nb);

	state.copyBytesByIndex(output, 0, state.length(), 0);
}

void ByteEncryptionAES::aes_decipher(ByteVector *input, ByteEncryptionAESExpandedKey *key, ByteVector *output) {
	ByteVector state = ByteVector(16);
	for (size_t i = 0; i < state.length(); i++) {
		state[i] = (*input)[i];
	}

	int nr = this->KeyNr(key->keysize);
	int nb = 4;
	int nk = this->KeyNk(key->keysize);

	addRoundKey(&state, key->w, nr*nb);

	for (int round = nr-1; round >= 1; round--) {
		invshiftrows(&state);
		invsubbytes(&state);
		addRoundKey(&state, key->w, round * nb);
		invmixcolumns(&state);
	}
	invshiftrows(&state);
	invsubbytes(&state);
	
	addRoundKey(&state, key->w, 0);

	state.copyBytesByIndex(output, 0, state.length(), 0);
}

uint32_t ByteEncryptionAES::subword(uint32_t word) {
	// replace each byte in word with corresponding byte in sbox lookup table
	byte w0 = (byte)(word >> 24) & 0xff;
	byte w1 = (byte)(word >> 16) & 0xff;
	byte w2 = (byte)(word >> 8) & 0xff;
	byte w3 = (byte)(word) & 0xff;
	return ((uint32_t)sbox[w0] << 24) | ((uint32_t)sbox[w1] << 16) | ((uint32_t)sbox[w2] << 8) | ((uint32_t)sbox[w3]);
}

void ByteEncryptionAES::subbytes(ByteVector *b) {
	assert(b->length() == 16);
	for (size_t i = 0; i < 16; i++) {
		(*b)[i] = sbox[(*b)[i]];
	}
}

void ByteEncryptionAES::invsubbytes(ByteVector *b) {
	assert(b->length() == 16);
	for (size_t i = 0; i < 16; i++) {
		(*b)[i] = inv_sbox[(*b)[i]];
	}
}

void ByteEncryptionAES::shiftrows(ByteVector *b) {
	assert(b->length() == 16);
	byte row[4];
	for (size_t i = 0; i < 4; i++) {
		for (size_t j = 0; j < 4; j++) {
			row[j] = (*b)[4 * j + i];
		}
		// left shift position i places
		for (size_t j = 0; j < 4; j++) {
			(*b)[4 * j + i] = row[(j + i) % 4];
		}
	}
}

void ByteEncryptionAES::invshiftrows(ByteVector *b) {
	assert(b->length() == 16);
	byte row[4];
	for (size_t i = 0; i < 4; i++) {
		for (size_t j = 0; j < 4; j++) {
			row[j] = (*b)[4 * j + i];
		}
		// left shift position i places
		for (size_t j = 0; j < 4; j++) {
			(*b)[4 * j + i] = row[(j - i) % 4];
		}
	}
}

void ByteEncryptionAES::mixcolumns(ByteVector *b) {
	ByteVector temp = ByteVector(16);
	temp.allBytes(0);
	for (size_t i = 0; i < 4; i++) {
		temp[4*i + 0] = (byte)(gmul(0x02, (*b)[4 * i + 0]) ^ gmul(0x03, (*b)[4 * i + 1]) ^ (*b)[4 * i + 2] ^ (*b)[4 * i + 3]);
		temp[4 * i + 1] = (byte)((*b)[4 * i + 0] ^ gmul(0x02, (*b)[4 * i + 1]) ^ gmul(0x03, (*b)[4 * i + 2]) ^ (*b)[4 * i + 3]);
		temp[4 * i + 2] = (byte)((*b)[4 * i + 0] ^ (*b)[4 * i + 1] ^ gmul(0x02, (*b)[4 * i + 2]) ^ gmul(0x03, (*b)[4 * i + 3]));
		temp[4 * i + 3] = (byte)(gmul(0x03, (*b)[4 * i + 0]) ^ (*b)[4 * i + 1] ^ (*b)[4 * i + 2] ^ gmul(0x02, (*b)[4 * i + 3]));
	}
	temp.copyBytesByIndex(b, 0, temp.length(), 0);
}

void ByteEncryptionAES::invmixcolumns(ByteVector *b) {
	ByteVector temp = ByteVector(16);
	temp.allBytes(0);
	for (size_t i = 0; i < 4; i++) {
		temp[4 * i + 0] = (byte)(gmul(0x0e, (*b)[4 * i + 0]) ^ gmul(0x0b, (*b)[4 * i + 1]) ^ gmul(0x0d, (*b)[4 * i + 2]) ^ gmul(0x09, (*b)[4 * i + 3]));
		temp[4 * i + 1] = (byte)(gmul(0x09, (*b)[4 * i + 0]) ^ gmul(0x0e, (*b)[4 * i + 1]) ^ gmul(0x0b, (*b)[4 * i + 2]) ^ gmul(0x0d, (*b)[4 * i + 3]));
		temp[4 * i + 2] = (byte)(gmul(0x0d, (*b)[4 * i + 0]) ^ gmul(0x09, (*b)[4 * i + 1]) ^ gmul(0x0e, (*b)[4 * i + 2]) ^ gmul(0x0b, (*b)[4 * i + 3]));
		temp[4 * i + 3] = (byte)(gmul(0x0b, (*b)[4 * i + 0]) ^ gmul(0x0d, (*b)[4 * i + 1]) ^ gmul(0x09, (*b)[4 * i + 2]) ^ gmul(0x0e, (*b)[4 * i + 3]));
	}
	temp.copyBytesByIndex(b, 0, temp.length(), 0);
}

// could just replace this with a table. AES256 only requires i = 1..29
byte ByteEncryptionAES::rcon(int i) {
	assert(i >= 1);
	byte rcon = 0x01;
	for (int j = 1; j < i; j++) {

		uint32_t temp = (rcon << 1);
		if (rcon >> 7 == 1) {
			temp ^= 0x11b;
		}
		rcon = temp;
	}
	return rcon;
}

// Galois Field (256) multiplication. A bit beyond me at the moment. Implementation taken from https://en.wikipedia.org/wiki/Rijndael_MixColumns
byte ByteEncryptionAES::gmul(byte a, byte b) {
	byte c = 0;
	for (int i = 0; i < 8; i++) {
		if ((b & 1) != 0) {
			c ^= a;
		}

		bool hi_set = ((a & 0x80) != 0);
		a <<= 1;
		if (hi_set) {
			a ^= 0x11B;
		}
		b >>= 1;
	}
	return c;
}

void ByteEncryptionAES::addRoundKey(ByteVector *state, uint32_t *w, size_t w_i) {

	for (size_t i = 0; i < 16; i++) {
		int offset = (int)i / 4;
		(*state)[i] ^= (byte)(0xff & (w[w_i + offset] >> (24 - (i % 4) * 8)));
	}
}