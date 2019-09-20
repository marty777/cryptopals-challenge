#include "ByteRandom.h"
#include <iostream>
#include <assert.h>


ByteRandom::ByteRandom()
{
	this->MT.resize(BYTERANDOM_MT19937_N);
	this->index = BYTERANDOM_MT19937_N + 1;
	this->lower_mask = (1 << BYTERANDOM_MT19937_R) - 1;
	this->upper_mask = ~(this->lower_mask) & BYTERANDOM_MT19937_W_MASK;
}


ByteRandom::~ByteRandom()
{
	this->MT.clear();
}

// seed and integer extraction implementation based on pseudocode from https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode 
void ByteRandom::m_seed(int seed) {
	this->index = BYTERANDOM_MT19937_N;
	this->MT[0] = seed;
	for (int i = 1; i < BYTERANDOM_MT19937_N; i++) {
		this->MT[i] = BYTERANDOM_MT19937_W_MASK & (BYTERANDOM_MT19937_F * (this->MT[i - 1] ^ (this->MT[i - 1] >> (BYTERANDOM_MT19937_W - 2))) + i);
	}
	this->m_twist();
}

uint32_t ByteRandom::m_rand() {
	if (this->index >= BYTERANDOM_MT19937_N) {
		if (this->index > BYTERANDOM_MT19937_N) {
			this->m_seed(5489);
		}
		this->m_twist();
	}

	uint32_t y = this->MT[this->index++];
	y ^= ((y >> BYTERANDOM_MT19937_U) & BYTERANDOM_MT19937_D);
	y ^= ((y << BYTERANDOM_MT19937_S) & BYTERANDOM_MT19937_B);
	y ^= ((y << BYTERANDOM_MT19937_T) & BYTERANDOM_MT19937_C);
	y ^= (y >> BYTERANDOM_MT19937_L);

	return (BYTERANDOM_MT19937_W_MASK & y);
}

// twist implemenation informed by https://create.stephan-brumme.com/mersenne-twister/
void ByteRandom::m_twist() {

	for (int i = 0; i < BYTERANDOM_MT19937_N; i++) {
		uint32_t bits = (this->MT[i] & this->upper_mask) | (this->MT[i + 1] & this->lower_mask);
		uint32_t bitsA = bits >> 1;
		if (bits % 2 != 0) {
			bitsA ^= BYTERANDOM_MT19937_A;
		}
		this->MT[i] = this->MT[(i + BYTERANDOM_MT19937_M) % BYTERANDOM_MT19937_N] ^ bitsA;
	}
	this->index = 0;
}


// random signed int between start and end using rand()
int ByteRandom::rand_range(int start, int end) {
	assert(end > start);
	return start + (rand() % (1 + end - start));
}

// inverts output from an M19937 twister to obtain the original element of the state array.
uint32_t ByteRandom::m_untemper(uint32_t input) {

	uint32_t x = input;
	x = ByteRandom::m_untemper_shift_xor_mask(x, BYTERANDOM_MT19937_L, true, 0xffffffff);
	x = ByteRandom::m_untemper_shift_xor_mask(x, BYTERANDOM_MT19937_T, false, BYTERANDOM_MT19937_C);
	x = ByteRandom::m_untemper_shift_xor_mask(x, BYTERANDOM_MT19937_S, false, BYTERANDOM_MT19937_B);
	x = ByteRandom::m_untemper_shift_xor_mask(x, BYTERANDOM_MT19937_U, true, BYTERANDOM_MT19937_D);
	return x;
}

uint32_t ByteRandom::m_untemper_shift_xor_mask(uint32_t input, uint32_t shift, bool right, uint32_t mask) {

	bool in[32];
	bool msk[32];
	bool out[32];
	for (int i = 0; i < 32; i++) {
		in[i] = (((input >> 31 - i) & 0x01) == 0) ? false : true;
		msk[i] = (((mask >> 31 - i) & 0x01) == 0) ? false : true;
	}

	// reverse the bit arrays if left shift
	if (!right) {
		bool in2[32];
		bool msk2[32];
		for (int i = 0; i < 32; i++) {
			in2[i] = in[31 - i];
			msk2[i] = msk[31 - i];
		}
		for (int i = 0; i < 32; i++) {
			in[i] = in2[i];
			msk[i] = msk2[i];
		}
	}

	for (int i = 0; i < 32; i++) {
		if (i < shift) {
			out[i] = in[i];
		}
		else {
			out[i] = in[i] ^ (msk[i] & out[i - shift] );
		}
	}

	// reverse if left shift
	if (!right) {
		bool out2[32];
		for (int i = 0; i < 32; i++) {
			out2[i] = out[31 - i];
		}
		for (int i = 0; i < 32; i++) {
			out[i] = out2[i];
		}
	}

	uint32_t output = 0;
	for (int i = 0; i < 32; i++) {
		output = output << 1;
		output |= (out[i] ? 0x1 : 0x0);
	}

	return output;
}
