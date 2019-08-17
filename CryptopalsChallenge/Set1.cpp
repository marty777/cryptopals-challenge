#include "ByteVector.h"
#include "PlaintextEvaluator.h"
#include <iostream>
using namespace std;


void Set1Challenge1() {
	//char *inputStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	//char *inputStr = "f013";
	char *inputStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	char *expectedOutput = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
	cout << "Input:\t" << inputStr << "\n";
	ByteVector bv = ByteVector(inputStr, HEX);
	ByteVector bv2 = ByteVector(expectedOutput, BASE64);
	char *output = bv.toStr(BASE64);
	cout << "Output:\t" << output << "\n";
	cout << (bv.equal(&bv2) ? "Output matches expected result\n" : "Output does not match expected") << "\n";
}

void Set1Challenge2() {
	char *input1 = "1c0111001f010100061a024b53535009181c";
	char *input2 = "686974207468652062756c6c277320657965";

	char *expectedOutput = "746865206b696420646f6e277420706c6179";
	cout << "Input 1:\t" << input1 << "\n";
	cout << "Input 2:\t" << input2 << "\n";
	ByteVector bv4 = ByteVector(expectedOutput, HEX);
	ByteVector bv = ByteVector(input1, HEX);
	ByteVector bv2 = ByteVector(input2, HEX);
	ByteVector bv3 = bv.xor(&bv2);
	cout << "Output:\t" << bv3.toStr(HEX) << "\n";
	cout << (bv3.equal(&bv4) ? "Output matches expected result\n" : "Output does not match expected") << "\n";
}

void Set1Challenge3() {
	char *input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
	ByteVector bv = ByteVector(input, HEX);
	ByteVector key = ByteVector("00", HEX);
	byte bestKey = 0;
	float bestScore = 10000000.0;
	for (byte i = 0; i < 127; i++) {
		key.setAtIndex(i, 0);
		ByteVector result = bv.xor(&key);
		string resultText(reinterpret_cast<char*>(result.toStr(ASCII)));
		float score = PlaintextEvaluator::score(resultText);
		if (score < bestScore) {
			bestScore = score;
			bestKey = i;
		}
	}
	key.setAtIndex(bestKey, 0);
	ByteVector result = bv.xor(&key);
	cout << "Best result: " << std::hex << (int)bestKey << " - " << bestScore << "\n";
	cout << "Plaintext: " << result.toStr(ASCII) << "\n";
}

int main() {
	cout << "Set 1 Challenge 1\n";
	Set1Challenge1();
	// Pause before continuing
	cout << "Press any key to continue...\n";
	getchar();
	cout << "Set 1 Challenge 2\n";
	Set1Challenge2();
	// Pause before continuing
	cout << "Press any key to continue...\n";
	getchar();
	cout << "Set 1 Challenge 3\n";
	Set1Challenge3();
	// Pause before continuing
	cout << "Press any key to continue...\n";
	getchar();
	return 0;
}
