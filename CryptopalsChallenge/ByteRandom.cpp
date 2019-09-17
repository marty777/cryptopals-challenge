#include "ByteRandom.h"
#include <iostream>


ByteRandom::ByteRandom()
{
	this->MT.resize(BYTERANDOM_MT19937_N);
	this->index = BYTERANDOM_MT19937_N + 1;
	this->lower_mask = (1 << BYTERANDOM_MT19937_R) - 1;
	this->upper_mask = ~(this->lower_mask) & BYTERANDOM_MT19937_W_MASK;
	std::cout << std::hex << this->lower_mask << " " << this->upper_mask << std::dec << std::endl;
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
}

int ByteRandom::m_rand() {
	if (this->index >= BYTERANDOM_MT19937_N) {
		if (this->index > BYTERANDOM_MT19937_N) {
			this->m_seed(5489);
		}
		this->m_twist();
	}

	int y = this->MT[index];
	y ^= ((y >> BYTERANDOM_MT19937_U) & BYTERANDOM_MT19937_D);
	y ^= ((y << BYTERANDOM_MT19937_S) & BYTERANDOM_MT19937_B);
	y ^= ((y << BYTERANDOM_MT19937_T) & BYTERANDOM_MT19937_C);
	y ^= (y >> BYTERANDOM_MT19937_L);

	this->index++;
	return (BYTERANDOM_MT19937_W_MASK & y);
}

int ByteRandom::test_rand(int in) {
	int y = in;
	y ^= ((y >> BYTERANDOM_MT19937_U) & BYTERANDOM_MT19937_D);
	y ^= ((y << BYTERANDOM_MT19937_S) & BYTERANDOM_MT19937_B);
	y ^= ((y << BYTERANDOM_MT19937_T) & BYTERANDOM_MT19937_C);
	y ^= (y >> BYTERANDOM_MT19937_L);
	return y;
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

	//const int firstHalf = BYTERANDOM_MT19937_N - BYTERANDOM_MT19937_M;
	//for (int i = 0; i < firstHalf; i++) {
	//	uint32_t bits = (this->MT[i] & this->upper_mask) | (this->MT[i + 1] & this->lower_mask);
	//	this->MT[i] = this->MT[i + BYTERANDOM_MT19937_M] ^ (bits >> 0x1) ^ ((bits & 1) * BYTERANDOM_MT19937_A);
	//}

	//for (int i = firstHalf; i < BYTERANDOM_MT19937_N - 1; i++) {
	//	uint32_t bits = (this->MT[i] & this->upper_mask) | (this->MT[i + 1] & this->lower_mask);
	//	this->MT[i] = this->MT[i - firstHalf] ^ (bits >> 0x1) ^ ((bits & 1) * BYTERANDOM_MT19937_A);
	//}
	//// last word
	//uint32_t bits = (this->MT[BYTERANDOM_MT19937_N - 1] & this->upper_mask) | (this->MT[0] & this->lower_mask);
	//this->MT[BYTERANDOM_MT19937_N - 1] ^ (bits >> 1) ^ ((bits & 0x1) * BYTERANDOM_MT19937_A);

	this->index = 0;
}