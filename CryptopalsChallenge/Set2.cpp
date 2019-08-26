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

void Set2Challenge11() {
	srand(0);

	// our carefully selected plaintext
	size_t inputlen = 1024;
	ByteVector input = ByteVector(inputlen);
	for (size_t i = 0; i < input.length(); i++) {
		input.setAtIndex(0xff, i);
	}
	ByteVector output = ByteVector(inputlen);
	
	int oracle_sucesses = 0;
	int trials = 1000;
	for (int i = 0; i < trials; i++) {
		bool detected_block_mode = false; // true for ecb, false for cbc
		bool actual_block_mode = ByteEncryption::aes_random_encrypt(&input, &output);
		int repeat_block_count = ByteEncryption::aes_repeated_block_count(&output);
		// this is probably an overly cautious metric, but I assume you can get occasional 
		// repeated blocks in a long enough stream using CBC.
		if (repeat_block_count * 16 > output.length() / 2) {
			detected_block_mode = true;
		}
		if (detected_block_mode == actual_block_mode) {
			oracle_sucesses++;
		}
	}
	cout << oracle_sucesses << " successes out of " << trials << " trial detections of AES ECB vs CBC cipher block mode." << endl;
}

void Set2Challenge12() {
	ByteVector post = ByteVector("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK", BASE64);
	ByteVector secretKey = ByteVector(16);
	secretKey.random();

	ByteVector output = ByteVector();

	// Determine block size and estimate length of appended bytes
	size_t last_len = 0;
	size_t block_size = 0;
	size_t append_size = 0;
	for (size_t i = 1; i < 255; i++) {
		ByteVector bv = ByteVector(i);
		ByteEncryption::aes_append_encrypt(&bv, &post, &secretKey, &output);
		size_t len = output.length();
		if (last_len != 0 && len != last_len) {
			block_size = len - last_len;
			append_size = last_len - i + 1;
			break;
		}
		last_len = len;
	}
	cout << "Inferred block size:\t" << block_size << endl;

	// Detect ECB vs CBC
	ByteVector input = ByteVector(1000);
	for (size_t i = 0; i < input.length(); i++) {
		input.setAtIndex(0xff, i);
	}
	ByteEncryption::aes_append_encrypt(&input, &post, &secretKey, &output);
	cout << "Detected block cipher mode:\t" << ((ByteEncryption::aes_repeated_block_count(&output) > 50) ? "ECB" : "CBC") << endl;

	// Decode appended bytes
	ByteVector decoded = ByteVector(append_size);
	ByteVector testInput = ByteVector(block_size);

	for (size_t i = 0; i < append_size; i++) {
		int blockindex = i / block_size;
		// our varying length input vector, all 0xff
		int input_size = block_size - 1 - (i % block_size);
		input.resize((size_t)input_size);
		for (size_t j = 0; j < input_size; j++) {
			input.setAtIndex(0xff, j);
		}
		ByteEncryption::aes_append_encrypt(&input, &post, &secretKey, &output);

		// test output againt all possible next bytes in block
		
		if (i < block_size) {
			// if < blocksize, fill in blocksize - i bytes of 0xff, and insert 
			// previously decoded bytes to positions blocksize-i to blocksize-1;
			for (size_t j = 0; j < block_size - i; j++) {
				testInput.setAtIndex(0xff, j);
			}
			decoded.copyBytesByIndex(&testInput, 0, i, block_size - 1 - i);
		}
		else {
			// copy last blocksize-1 decoded bytes to testInput.
			decoded.copyBytesByIndex(&testInput, i - (block_size - 1), block_size - 1, 0);
		}

		// vary final byte in test input to find a match against the output block at blockindex
		ByteVector outputComparisonBlock = ByteVector(16);
		output.copyBytesByIndex(&outputComparisonBlock, block_size * blockindex, block_size, 0);
		for (int j = 0; j <= 0xff; j++) {
			ByteVector testOutput = ByteVector();
			ByteVector firstBlockTestOutput = ByteVector(block_size);
			testInput.setAtIndex((byte)j, block_size - 1);
			ByteEncryption::aes_append_encrypt(&testInput, &post, &secretKey, &testOutput);
			testOutput.copyBytesByIndex(&firstBlockTestOutput, 0, 16, 0);
			
			if(outputComparisonBlock.equal(&firstBlockTestOutput)) {
				decoded.setAtIndex((byte)j, i);
				break;
			}
		}
	}

	cout << "Decoded: " << decoded.toStr(ASCII) << endl;
}

int Set2() {
	cout << "### SET 2 ###" << endl;
	cout << "Set 2 Challenge 9" << endl;
	Set2Challenge9();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 2 Challenge 10" << endl;
	Set2Challenge10();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 2 Challenge 11" << endl;
	Set2Challenge11();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 2 Challenge 12" << endl;
	Set2Challenge12();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	return 0;
}