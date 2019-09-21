#pragma once
#include "ByteVector.h"
#include <vector>


// MT19937 parameters
#define BYTERANDOM_MT19937_W 32				// word size (bits)
#define BYTERANDOM_MT19937_N 624			// degree of recurrence
#define BYTERANDOM_MT19937_M 397			// middle word offset
#define BYTERANDOM_MT19937_R 31				// separation point of one word

#define BYTERANDOM_MT19937_A 0x9908B0DFUL	// coefficients of the rational normal form twist matrix
#define BYTERANDOM_MT19937_B 0x9D2C5680UL	// TGFSR(R) tempering bitmask
#define BYTERANDOM_MT19937_C 0xEFC60000UL	// TGFSR(R) tempering bitmask
#define BYTERANDOM_MT19937_S 7				// GFSR(R) tempering bit shift
#define BYTERANDOM_MT19937_T 15				// GFSR(R) tempering bit shift
#define BYTERANDOM_MT19937_U 11				// additional Mersenne Twister tempering bit shifts/mask
#define BYTERANDOM_MT19937_D 0xFFFFFFFFUL	// additional Mersenne Twister tempering bit shifts/masks
#define BYTERANDOM_MT19937_L 18				// additional Mersenne Twister tempering bit shifts/masks

#define BYTERANDOM_MT19937_F 1812433253UL 	// Not actually sure what to call this parameter

#define BYTERANDOM_MT19937_W_MASK 0xFFFFFFFFUL	

class ByteRandom

{
public:
	std::vector<uint32_t> MT;
	int index;
	int lower_mask;
	int upper_mask;

	ByteRandom();
	~ByteRandom();

	void m_seed(int seed);
	uint32_t m_rand();

	static int rand_range(int start, int end);
	static void uint32_to_ByteVector(uint32_t input, ByteVector *output);

	static uint32_t m_untemper(uint32_t input);
	static uint32_t m_untemper_shift_xor_mask(uint32_t input, uint32_t shift, bool direction, uint32_t mask);

private:
	void m_twist();
};

