#include "ByteVector.h"
#include "PlaintextEvaluator.h"
#include <iostream>
#include <fstream>
using namespace std;


void Set1Challenge1() {
	//char *inputStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	//char *inputStr = "f013";
	char *inputStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	char *expectedOutput = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
	cout << "Input:\t" << inputStr << endl;
	ByteVector bv = ByteVector(inputStr, HEX);
	ByteVector bv2 = ByteVector(expectedOutput, BASE64);
	char *output = bv.toStr(BASE64);
	cout << "Output:\t" << output << endl;
	cout << (bv.equal(&bv2) ? "Output matches expected result\n" : "Output does not match expected") << endl;
}

void Set1Challenge2() {
	char *input1 = "1c0111001f010100061a024b53535009181c";
	char *input2 = "686974207468652062756c6c277320657965";

	char *expectedOutput = "746865206b696420646f6e277420706c6179";
	cout << "Input 1:\t" << input1 << endl;
	cout << "Input 2:\t" << input2 << endl;
	ByteVector bv4 = ByteVector(expectedOutput, HEX);
	ByteVector bv = ByteVector(input1, HEX);
	ByteVector bv2 = ByteVector(input2, HEX);
	ByteVector bv3 = bv.xor(&bv2);
	cout << "Output:\t\t" << bv3.toStr(HEX) << endl;
	cout << (bv3.equal(&bv4) ? "Output matches expected result\n" : "Output does not match expected") << endl;
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
	cout << "Best result:\t" << std::hex << (int)bestKey << " - " << bestScore << endl;
	cout << "Plaintext:\t" << result.toStr(ASCII) << endl;
}

void Set1Challenge4() {
	char *filePath = "../challenge-files/set1/4.txt";
	ifstream in(filePath);
	if (!in) {
		cout << "Cannot open input file.\n";
		return;
	}
	char line[255];
	int linecount = 0;
	while (in) {
		in.getline(line, 255);
		// test possible key bytes and print if below a specific threshold for manual inspection.
		float threshold = 0.8;
		ByteVector line_bv = ByteVector(line, HEX);
		ByteVector key_bv = ByteVector("00", HEX);
		for (byte i = 0; i < 255; i++) {
			key_bv.setAtIndex(i, 0);
			ByteVector result = line_bv. xor (&key_bv);
			string resultText(reinterpret_cast<char*>(result.toStr(ASCII)));
			float score = PlaintextEvaluator::score(resultText);
			if (score < threshold) {
				cout << "Line #: " << dec << (int)linecount << " Key byte: 0x" << hex << (int)i << " Score: " << score << " " << resultText << endl;
			}
		}
		linecount++;
	}
	in.close();
}

void Set1Challenge5() {
	char *input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
	char *key = "ICE";
	char *expectedResult = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
	ByteVector input_bv = ByteVector(input, ASCII);
	ByteVector key_bv = ByteVector(key, ASCII);
	ByteVector expected_bv = ByteVector(expectedResult, HEX);
	ByteVector result = input_bv.xor(&key_bv);
	cout << "Input:\t" << input_bv.toStr(ASCII) << endl;
	cout << "Key:\t" << key_bv.toStr(ASCII) << endl;
	cout << "Output:\t" << result.toStr(HEX) << endl;
	cout << (expected_bv.equal(&result) ? "Output matches expected result\n" : "Output does not match expected") << endl;
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
	cout << "Set 1 Challenge 4\n";
	Set1Challenge4();
	// Pause before continuing
	cout << "Press any key to continue...\n";
	getchar();
	cout << "Set 1 Challenge 5\n";
	Set1Challenge5();
	// Pause before continuing
	cout << "Press any key to continue...\n";
	getchar();
	return 0;
}
