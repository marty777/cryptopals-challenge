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


// reverses the operation input = output ^ (output >> shift)
// see http://krypt05.blogspot.com/2015/10/reversing-shift-xor-operation.html
uint32_t ByteRandom::m_untemper_rshift_xor(uint32_t input, uint32_t shift) {

	// break up the input value into chunks of shift bytes (or the remainder, for the last chunk)
	int numchunks = 32 / shift;
	if (numchunks * shift < 32) {
		numchunks++;
	}
	uint32_t *chunks = (uint32_t *)malloc(sizeof(uint32_t) * numchunks);
	for (int i = 0; i < numchunks; i++) {
		int numbits = shift;
		if (i == numchunks - 1 && 32 % shift != 0) {
			numbits = 32 - ((32 / shift) * shift);
		}
		uint32_t mask = 0;
		for (int j = 0; j < numbits; j++) {
			mask = (mask << 1) | 0x01;
		}
		if (i < numchunks - 1) {
			chunks[i] = mask & (input >> (32 - (shift * (i + 1))));
		}
		else {
			chunks[i] = input & mask;
		}
	}

	// operating on each chunk in sequence, xor with previous chunk to obtain output bits
	for (int i = 1; i < numchunks; i++) {
		uint32_t mask = 0;
		int numbits = shift;
		int offset = 0;
		if (i == numchunks - 1 && 32 % shift != 0) {
			numbits = 32 - ((32 / shift) * shift);
			offset = shift - numbits;
		}
		for (int j = 0; j < numbits; j++) {
			mask = (mask << 1) | 0x01;
		}
		chunks[i] = (chunks[i] ^ (chunks[i - 1] >> offset)) & mask;
	}

	// stitch the bits back together
	uint32_t output = 0;
	for (int i = 0; i < numchunks; i++) {
		uint32_t mask = 0;
		int numbits = shift;
		int offset = (32 - ((i + 1)* shift));
		if (i == numchunks - 1 && 32 % shift != 0) {
			numbits = 32 - ((32 / shift) * shift);
			offset = 0;
		}
		for (int j = 0; j < numbits; j++) {
			mask = (mask << 1) | 0x01;
		}
		output |= (chunks[i] & mask) << offset;
	}

	free(chunks);

	return output;
}

// reverses the operation input = output ^ ((output << shift) & and)
uint32_t ByteRandom::m_untemper_lshift_and_xor(uint32_t input, uint32_t shift, uint32_t and) {

}