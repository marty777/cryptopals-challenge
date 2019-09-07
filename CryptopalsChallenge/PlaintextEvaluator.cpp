#include "PlaintextEvaluator.h"

PlaintextEvaluator::PlaintextEvaluator()
{
}


PlaintextEvaluator::~PlaintextEvaluator()
{
}

// Lower scores are closer to the average relative character frequency distribution
// in english language text.
// Needs work.
float PlaintextEvaluator::score(std::string input) {
	// score based on character frequency compared to english language distribution
	// Frequencies taken from https://en.wikipedia.org/wiki/Letter_frequency
	const float frequencies[] = {	
									0.08167f, // a
									0.01492f, // b
									0.02782f, // c
									0.04253f, // d
									0.12702f, // e
									0.02228f, // f
									0.02015f, // g
									0.06094f, // h
									0.06966f, // i
									0.00153f, // j
									0.00772f, // k
									0.04025f, // l
									0.02406f, // m
									0.06749f, // n
									0.07507f, // o
									0.01929f, // p
									0.00095f, // q
									0.05987f, // r
									0.06327f, // s
									0.09056f, // t
									0.02758f, // u
									0.00978f, // v
									0.02360f, // w
									0.00150f, // x
									0.01974f, // y
									0.00074f  // z
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
		else if (/*input[i] <= 0x1F ||*/ input[i] > 0x7F) {
			penalty_count++;
		}
		
		
	}

	float score = 0;
	for (int i = 0; i < 26; i++) {
		score += abs(frequencies[i] - ((float)(counts[i]) / (float)(total)));
	}

	// This seems to give worse results. Probably just need to omit characters like line breaks.
	score += 0.5f * penalty_count;

	return score;
}

float PlaintextEvaluator::score(ByteVector *input) {
	std::string str = input->toStr(ASCII);
	return PlaintextEvaluator::score(str);
}
