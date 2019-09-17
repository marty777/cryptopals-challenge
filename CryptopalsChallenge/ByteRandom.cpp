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

// random signed int between start and end using rand()
int ByteRandom::rand_range(int start, int end) {
	assert(end > start);
	return start + (rand() % (1 + end - start));
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