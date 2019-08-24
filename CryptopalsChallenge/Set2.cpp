#include "ByteVector.h"
#include "ByteEncryption.h"
#include "PlaintextEvaluator.h"
#include <iostream>
#include <fstream>

using namespace std;

void Set2Challenge9() {
	
	char * input = "YELLOW SUBMARINE";
	char * expectedOutput = "YELLOW SUBMARINE\x04\x04\x04\x04";
	ByteVector bv = ByteVector(input, ASCII);
	ByteVector expectedBv = ByteVector(expectedOutput, ASCII);
	bv.padToLength(20, 0x04);
	cout << bv.toStr(ASCII) << endl;
	cout << (bv.equal(&expectedBv) ? "Output matches expected result\n" : "Output does not match expected") << endl;
}

void Set2Challenge10() {
	char * key = "YELLOW SUBMARINE";					
	char * testInput = "YELLOW SUBMARINEMERRY GENTLEMAN ERNEST WITNESSES"; // nonsense that's 48 bytes long
	char *filePath = "../challenge-files/set2/10.txt";

	
	ByteVector testIn = ByteVector(testInput, ASCII);
	ByteVector testOut = ByteVector(testIn.length());
	ByteVector testKey = ByteVector("HELLO SUBSTITUTE", ASCII);
		
	ByteVector testIv = ByteVector(16);
	for (size_t i = 0; i < 16; i++) {
		testIv.setAtIndex(15, i);
	}
	cout << "Test input:\t" << testInput << endl;
	ByteEncryption::aes_cbc_encrypt(&testIn, &testKey, &testOut, &testIv, true);
	cout << "Test encrypt:\t" << testOut.toStr(ASCII) << endl;
	ByteVector testOut2 = ByteVector(testIn.length());
	ByteEncryption::aes_cbc_encrypt(&testOut, &testKey, &testOut2, &testIv, false);
	cout << "Test decrypt:\t" << testOut2.toStr(ASCII) << endl;

	ifstream f;
	string input;

	f.open(filePath);
	f.seekg(0, std::ios::end);
	input.reserve(f.tellg());
	f.seekg(0, std::ios::beg);

	input.assign((std::istreambuf_iterator<char>(f)),
		std::istreambuf_iterator<char>());

	f.close();

	ByteVector bv = ByteVector(&input[0], BASE64);
	ByteVector output = ByteVector(bv.length());
	ByteVector keyBv = ByteVector(key, ASCII);
	ByteVector iv = ByteVector(16);
	for (size_t i = 0; i < 16; i++) {
		iv.setAtIndex(0x00, i);
	}
	//cout << bv.toStr(BASE64) << endl;
	ByteEncryption::aes_cbc_encrypt(&bv, &keyBv, &output, &iv, false);
	cout << output.toStr(ASCII) << endl;
}

int Set2() {
	cout << "### SET 2 ###" << endl;
	cout << "Set 2 Challenge 9" << endl;
	Set2Challenge9();
	// Pause before continuing
	cout << "Press any key to continue..." << endl;
	getchar();
	cout << "Set 2 Challenge 10" << endl;
	Set2Challenge10();
	// Pause before continuing
	cout << "Press any key to continue..." << endl;
	getchar();
	return 0;
}