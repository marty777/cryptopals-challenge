#include "PlaintextEvaluator.h"

PlaintextEvaluator::PlaintextEvaluator()
{
}


PlaintextEvaluator::~PlaintextEvaluator()
{
}

// Lower scores are closer to the average relative character frequency distribution
// in english language text.
float PlaintextEvaluator::score(std::string input) {
	// score based on character frequency compared to english language distribution
	// Frequencies taken from https://en.wikipedia.org/wiki/Letter_frequency
	const float frequencies[] = {	
									0.08167, // a
									0.01492, // b
									0.02782, // c
									0.04253, // d
									0.12702, // e
									0.02228, // f
									0.02015, // g
									0.06094, // h
									0.06966, // i
									0.00153, // j
									0.00772, // k
									0.04025, // l
									0.02406, // m
									0.06749, // n
									0.07507, // o
									0.01929, // p
									0.00095, // q
									0.05987, // r
									0.06327, // s
									0.09056, // t
									0.02758, // u
									0.00978, // v
									0.02360, // w
									0.00150, // x
									0.01974, // y
									0.00074  // z
								};

	// Add a penalty for characters that we don't expect to see in ASCII text. Everything from 0x00 to 0x1F are control characters and probably
	// won't appear. Anything above 0x7F is outside of the non-extended ASCII definition 
	int penalty_count = 0;

	int counts[26];
	for (int i = 0; i < 26; i++) {
		counts[i] = 0;
	}
	int total = 0;
	for (size_t i = 0; i < input.length(); i++) {
		if (input[i] >= 0x41 && input[i] <= 0x5A) {
			counts[input[i] - 0x41]++;
			total++;
		}
		else if (input[i] >= 0x61 && input[i] <= 0x7A) {
			counts[input[i] - 0x61]++;
			total++;
		}
		// penalty characters
		else if (input[i] <= 0x1F || input[i] > 0x7F) {
			penalty_count++;
		}
	}

	float score = 0;
	for (int i = 0; i < 26; i++) {
		score += abs(frequencies[i] - ((float)(counts[i]) / (float)(total)));
	}

	score += 0.1 * penalty_count;

	return score;
}