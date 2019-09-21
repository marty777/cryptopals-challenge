#include "Set3.h"
#include "ByteVector.h"
#include "ByteEncryption.h"
#include "ByteRandom.h"
#include "PlaintextEvaluator.h"
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>


using namespace std;

void printAttemptedPartial(ByteVector *bv, size_t partial_index_start, size_t partial_index_end, bool ascii, size_t index, size_t partial_index2) {
	cout << index << "\t";
	for (size_t i = 0; i < bv->length(); i++) {
		if (i == partial_index_start) {
			cout << "|";
		}
		if (ascii) {
			cout << bv->atIndex(i);
		}
		else {
			cout << std::hex << (int)bv->atIndex(i) << std::dec;
		}
		if (i == partial_index_end) {
			cout << "|";
		}
		if (i == partial_index2 && partial_index2 != partial_index_end) {
			cout << "|";
		}
	}
	cout << endl;
}

size_t minsize(size_t a, size_t b) { return (a < b ? a : b); }
size_t maxsize(size_t a, size_t b) { return (a > b ? a : b); }

void Set3Challenge17() {
	const size_t block_size = 16; // I hope we can take as given
	vector<ByteVector> strings;
	strings.resize(10);
	strings[0] = ByteVector("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", BASE64);
	strings[1] = ByteVector("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", BASE64);
	strings[2] = ByteVector("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", BASE64);
	strings[3] = ByteVector("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", BASE64);
	strings[4] = ByteVector("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", BASE64);
	strings[5] = ByteVector("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", BASE64);
	strings[6] = ByteVector("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", BASE64);
	strings[7] = ByteVector("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", BASE64);
	strings[8] = ByteVector("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", BASE64);
	strings[9] = ByteVector("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93", BASE64);
	
	ByteVector secretKey = ByteVector(16);
	ByteVector iv = ByteVector(16);
	secretKey.random();
	iv.random();
	
	ByteVector output = ByteVector();
	ByteEncryption::challenge17encrypt(&strings, &secretKey, &output, &iv, false);
	output.printHexStrByBlocks(16);
	cout << "Decryption padding valid: " << (ByteEncryption::challenge17paddingvalidate(&output, &secretKey, &iv) ? "true" : "false") << endl ;

	ByteVector decoded = ByteVector(output.length());
	// overflow condition at -1 due to unsigned hence odd break condition
	for (size_t i = output.length() - 1; i >= 0 && i < output.length(); i--) {
		size_t block_index = i / block_size;
		size_t byte_index = (i % block_size);
		ByteVector testOutput = ByteVector(block_size * (block_index + 1));
		ByteVector testIv = ByteVector(iv);
		bool found = false;
		byte foundByte = 0;
		byte paddingByte = (byte)(block_size - byte_index);
		byte currentCipheredXORByte = 0;
		if (block_index == 0) {
			currentCipheredXORByte = iv.atIndex(byte_index);
		}
		else {
			currentCipheredXORByte = output.atIndex(block_size * (block_index - 1) + byte_index);
		}
		for (int j = 0; j <= 0xff; j++) {
			output.copyBytesByIndex(&testOutput, 0, testOutput.length(), 0);
			iv.copyBytes(&testIv);

			if (block_index == 0) {
				if (testIv.atIndex(byte_index) == (byte)j) {
					continue;
				}
				for (size_t k = block_size - 1; k > byte_index; k--) {
					// modify IV to generate valid padding with known decoded bytes
					byte mask = decoded.atIndex(k) ^ paddingByte;
					testIv.setAtIndex(iv.atIndex(k) ^ mask, k);
				}
				testIv.setAtIndex((byte)j, byte_index);
			}
			else {
				if (testOutput.atIndex(((block_index - 1) * block_size) + byte_index) == (byte)j) {
					continue;
				}
				for (size_t k = block_size - 1; k > byte_index; k--) {
					// modify ciphered bytes to generate valid padding with known decoded bytes
					size_t index = ((block_index)* block_size) + k;
					byte mask = decoded.atIndex(index) ^ paddingByte;
					testOutput.setAtIndex(output.atIndex(index - block_size) ^ mask, index - block_size);
				}
				testOutput.setAtIndex((byte)j, ((block_index - 1) * block_size) + byte_index);
			}

			if (ByteEncryption::challenge17paddingvalidate(&testOutput, &secretKey, &testIv)) {
				found = true;
				foundByte = j;
			}

		}
		if (found) {
			byte preXor = foundByte ^ paddingByte;
			decoded.setAtIndex(currentCipheredXORByte ^ preXor, i);
		}
		else {
			// must have already been valid
			decoded.setAtIndex(paddingByte, i);
		}
	}
	
	ByteVector stripped = ByteVector();
	ByteEncryptionError err = ByteEncryptionError();
	ByteEncryption::pkcs7PaddingValidate(&decoded, &stripped, &err);
	if (err.hasErr()) {
		cout << "Padding could not be stripped from decoded string:" << decoded.toStr(ASCII) << endl;
	}
	else {
		cout << "Decoded string: " << stripped.toStr(ASCII) << endl;
	}
}

void Set3Challenge18() {
	ByteVector input = ByteVector("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==", BASE64);
	ByteVector key = ByteVector("YELLOW SUBMARINE", ASCII);
	ByteVector counter = ByteVector(16);
	unsigned long long nonce = 0;
	unsigned long long count = 0;
	
	ByteVector output = ByteVector(input.length());
	ByteEncryption::aes_ctr_encrypt(&input, &key, &output, nonce);
	cout << "Decrypted string: " << output.toStr(ASCII) << endl;
}

void Set3Challenge19() {
	unsigned long long secretNonce = rand();
	ByteVector secretKey = ByteVector(16);
	secretKey.random();

	vector<ByteVector> inputs;
	size_t max_keylen = 0; // length of longest string in inputs.

	char *filePath = "../challenge-files/set3/19.txt";
	ifstream in(filePath);
	if (!in) {
		cout << "Cannot open input file.\n";
		return;
	}
	char line[255];
	int linecount = 0;
	while (in) {
		in.getline(line, 255);
		// read in line and seperately CTR encrypt using secret key and nonce
		if (strlen(line) > 0) {
			ByteVector bv = ByteVector(line, BASE64);
			ByteVector output = ByteVector(bv.length());
			ByteEncryption::aes_ctr_encrypt(&bv, &secretKey, &output, secretNonce);
			inputs.push_back(&output);
			if (output.length() > max_keylen) {
				max_keylen = output.length();
			}
			linecount++;
		}
	}
	in.close();

	// This is going to be trial and error, which is sort of the point of the exercise.

	// 1) Let's look for possible line starters/cribs.
	vector<ByteVector> initialTests;
	initialTests.push_back(ByteVector("This ", ASCII));
	initialTests.push_back(ByteVector("this ", ASCII));
	initialTests.push_back(ByteVector("A ", ASCII));
	initialTests.push_back(ByteVector("a ", ASCII));
	initialTests.push_back(ByteVector("The ", ASCII));
	initialTests.push_back(ByteVector("the ", ASCII));
	initialTests.push_back(ByteVector("I ", ASCII));
	initialTests.push_back(ByteVector("i ", ASCII));
	
	
	int initialTestIndex = 0;
	ByteVector keystream = ByteVector(max_keylen);
	keystream.allBytes(0);
	
	bool initialFound = false;
	size_t lockedIndex = 0;

	cout << "A set of possible line beginnings will be tested against all inputs.\nKeep hitting enter until you see plausible line beginnings appearing in the section of each line denoted by | characters." << endl;
	cout << "Once you've found a possible set of starting decryption bytes, type 'lock' to continue to stage 2" << endl;
	cout << "Press enter to continue..." << endl;
	getchar();

	while (initialTestIndex < initialTests.size() && !initialFound) {
		ByteVector testText = ByteVector(initialTests[initialTestIndex]);
		initialTestIndex++;
		for (size_t i = 0; i < inputs.size() && !initialFound; i++) {
			cout << "Testing '" << testText.toStr(ASCII) << "' at index " << i << endl;
			ByteVector trial = ByteVector(inputs[i]);
			ByteVector xorBytes = ByteVector(testText.length());
			trial.copyBytesByIndex(&xorBytes, 0, xorBytes.length(), 0);
			xorBytes.xorByIndex(&testText, 0, xorBytes.length(), 0);
			// try against each input for inspection
			for (size_t j = 0; j < inputs.size(); j++) {
				ByteVector temp = ByteVector(inputs[j]);
				temp.xorByIndex(&xorBytes, 0, xorBytes.length(), 0);
				printAttemptedPartial(&temp, 0, xorBytes.length() - 1, true, j, xorBytes.length() - 1);
			}
			cout << "Key bytes: " << endl;
			xorBytes.printHexStrByBlocks(HEX);
			cout << "Press enter to continue or type lock:";
			
			string inputStr;
			std::getline(std::cin, inputStr);

			if (inputStr == "lock" || inputStr == "Lock" || inputStr == "LOCK") {
				xorBytes.copyBytesByIndex(&keystream, 0, xorBytes.length(), 0);
				initialFound = true;
				lockedIndex = xorBytes.length();
			}
		}
	}

	bool decoded = false;
	ByteVector trialBytes = ByteVector();
	size_t trialIndex = 0;
	while (!decoded) {
		ByteVector trialInput = ByteVector();
		ByteVector trialKeyStream = ByteVector(keystream);
		ByteVector xorBytes = ByteVector();
		if (trialBytes.length() > 0) {
			trialInput = ByteVector(inputs[trialIndex]);
			xorBytes = ByteVector(trialBytes.length());
			for (size_t i = lockedIndex; i < trialInput.length() && i < trialBytes.length() + lockedIndex; i++) {
				xorBytes.setAtIndex(trialInput.atIndex(i) ^ trialBytes.atIndex(i - lockedIndex), i - lockedIndex);
			}
			for(size_t i = lockedIndex; i < trialKeyStream.length() && i < lockedIndex + xorBytes.length(); i++) {
				trialKeyStream.setAtIndex(xorBytes.atIndex(i - lockedIndex), i);
			}
		}
		for (size_t i = 0; i < inputs.size(); i++) {
			ByteVector partial = ByteVector(inputs[i]);
			partial.xorWithStream(&trialKeyStream);
			printAttemptedPartial(&partial, 0, lockedIndex -1, true, i, lockedIndex - 1 + (trialBytes.length()));
		}
		cout << "Key bytes: " << endl;
		keystream.printHexStrByBlocks(16);
		cout << "Enter possible next characters on a line to test them. Type 'lock' to lock in a guess. Type 'back' to remove a byte from the locked keystream:";
		string inputStr;
		getline(cin, inputStr);
		if (inputStr == "lock" || inputStr == "Lock" || inputStr == "LOCK") {
			trialKeyStream.copyBytesByIndex(&keystream, 0, keystream.length(), 0);
			//xorBytes.copyBytesByIndex(&keystream, 0, xorBytes.length(), lockedIndex);
			lockedIndex += xorBytes.length();
			trialBytes.resize(0);
			if (lockedIndex == keystream.length()) {
				decoded = true;
			}
		}
		else if (inputStr == "back" || inputStr == "Back" || inputStr == "BACK") {
			keystream.setAtIndex(0, lockedIndex-1);
			lockedIndex--;
			trialBytes.resize(0);
		}
		else {
			std::vector<char> cstr(inputStr.c_str(), inputStr.c_str() + inputStr.size() + 1);
			char *in = (char *)malloc(cstr.size());
			for (size_t i = 0; i < cstr.size(); i++) {
				in[i] = cstr[i];
			}
			trialBytes = ByteVector(in, ASCII);
			delete[] in;
			cout << "Enter input index to test:";
			string inputStr2;
			int nextIndex;
			getline(cin, inputStr2);
			// not bothering with exception handling
			nextIndex = stoi(inputStr2);
			trialIndex = nextIndex;
		}
	}
	
	cout << "Determined XOR bytes: " << endl;
	keystream.printHexStrByBlocks(16);
	cout << "Actual XOR bytes:" << endl;
	ByteVector xorActualIn = ByteVector(keystream.length());
	xorActualIn.allBytes(0);
	ByteVector xorActualOut = ByteVector(keystream.length());
	ByteEncryption::aes_ctr_encrypt(&xorActualIn, &secretKey, &xorActualOut, secretNonce);
	xorActualOut.printHexStrByBlocks(16);

	
}

void Set3Challenge20() {
	unsigned long long secretNonce = rand();
	ByteVector secretKey = ByteVector(16);
	secretKey.random();

	vector<ByteVector> inputs;
	size_t max_keylen = 0; // length of longest string in inputs.
	size_t min_keylen = 1024;

	char *filePath = "../challenge-files/set3/20.txt";
	ifstream in(filePath);
	if (!in) {
		cout << "Cannot open input file.\n";
		return;
	}
	char line[255];
	int linecount = 0;
	while (in) {
		in.getline(line, 255);
		// read in line and seperately CTR encrypt using secret key and nonce
		if (strlen(line) > 0) {
			ByteVector bv = ByteVector(line, BASE64);
			ByteVector output = ByteVector(bv.length());
			ByteEncryption::aes_ctr_encrypt(&bv, &secretKey, &output, secretNonce);
			inputs.push_back(&output);
			if (output.length() > max_keylen) {
				max_keylen = output.length();
			}
			if (output.length() < min_keylen) {
				min_keylen = output.length();
			}
			linecount++;
		}
	}
	in.close();

	// truncate all inputs to the minimum length
	for (size_t i = 0; i < inputs.size(); i++) {
		inputs[i].resize(min_keylen);
	}

	ByteVector keystream = ByteVector(min_keylen);

	// solve statistically
	for (size_t i = 0; i < keystream.length(); i++) {
		float bestScore = 100000.0f;
		int bestByte = 0;
		ByteVector slice = ByteVector(inputs.size());
		for (int j = 0x0; j <= 0xff; j++) {
			for (size_t k = 0; k < inputs.size(); k++) {
				slice.setAtIndex(inputs[k].atIndex(i) ^ (byte)j, k);
			}
			float score = PlaintextEvaluator::score(&slice);
			if (score < bestScore) {
				bestScore = score;
				bestByte = j;
			}
		}
		keystream.setAtIndex((byte)bestByte, i);
	}

	cout << "Determined XOR bytes:" << endl;
	keystream.printHexStrByBlocks(16);

	cout << "Actual XOR bytes:" << endl;
	ByteVector xorActualIn = ByteVector(keystream.length());
	xorActualIn.allBytes(0);
	ByteVector xorActualOut = ByteVector(keystream.length());
	ByteEncryption::aes_ctr_encrypt(&xorActualIn, &secretKey, &xorActualOut, secretNonce);
	xorActualOut.printHexStrByBlocks(16);

	cout << "Difference:" << endl;
	ByteVector diff = ByteVector(keystream);
	diff.xorWithStream(&xorActualOut);
	diff.printHexStrByBlocks(16);

	cout << "Decryption: " << endl;
	for (size_t i = 0; i < inputs.size(); i++) {
		ByteVector decode = ByteVector(inputs[i]);
		decode.xorWithStream(&keystream);
		cout << i << "\t" << decode.toStr(ASCII) << endl;
	}
}

void Set3Challenge21() {
	int results5489[] = { -795755684, 581869302, -404620562, -708632711, 545404204, -133711905, -372047867, 949333985, -1579004998, 1323567403 };
	int results42[] = { 1608637542, -873841229, -211680420, 787846414, -1151077270, -946219961, -1723748676, -1731515372, 670094950, 1914837113 };
	int results777[] = { 655685735, -1518486737, 1298611771, 862112678, 266444375, -1562275919, 1975085127, 1065408157, -707581313, -1874628492 };

	ByteRandom random = ByteRandom();
	random.m_seed(5489);
	bool failed = false;
	for (int i = 0; i < 10; i++) {
		int rand = random.m_rand();
		if (rand != results5489[i]) {
			failed = true;
			break;
		}
	}
	cout << "Test of seed 5489 " << (failed ? "failed" : "succeeded") << endl;

	random.m_seed(42);
	failed = false;
	for (int i = 0; i < 10; i++) {
		int rand = random.m_rand();
		if (rand != results42[i]) {
			failed = true;
			break;
		}
	}
	cout << "Test of seed 42 " << (failed ? "failed" : "succeeded") << endl;

	random.m_seed(777);
	failed = false;
	for (int i = 0; i < 10; i++) {
		int rand = random.m_rand();
		if (rand != results777[i]) {
			failed = true;
			break;
		}
	}
	cout << "Test of seed 777 " << (failed ? "failed" : "succeeded") << endl;
}

void Set3Challenge22() {
	ByteRandom random;
	int wait1 = random.rand_range(40, 1000);
	std::time_t start = std::time(nullptr);
	cout << "Simulating waiting " << wait1 << " seconds..." << endl;
	cout << "Seeding..." << endl;
	std::time_t now = start + wait1;
	random.m_seed((int)now);
	int wait2 = random.rand_range(40, 1000);
	cout << "Simulating waiting " << wait2 << " seconds..." << endl;
	int result = random.m_rand();
	std:time_t final = start + wait1 + wait2;
	cout << "First result: " << result << endl;

	// seed recovery
	std::time_t now2 = final;
	cout << "Recovering seed..." << endl;
	bool found = false;
	int epoch_range = 10000; // how many seconds back we want to go to test timestamps
	for (std::time_t i = now2; i >= now2 - epoch_range; i--) {
		random.m_seed((int)i);
		if (random.m_rand() == result) {
			cout << "Recovered seed " << (int) i << endl;
			cout << "Actual seed " << (int)now << endl;
			found = true;
			break;
		}
	}
	if (!found) {
		cout << "Failed to recover seed between " << now2 - epoch_range << " and " << now2 << endl;
	}
}

void Set3Challenge23() {
	
	ByteRandom rand = ByteRandom();
	rand.m_seed(1000);
	ByteRandom clonedRand = ByteRandom();
	cout << "Cloning previously initialized MT19937..." << endl;
	for (int i = 0; i < BYTERANDOM_MT19937_N; i++) {
		clonedRand.MT[i] = ByteRandom::m_untemper(rand.m_rand());
	}
	clonedRand.index = BYTERANDOM_MT19937_N;
	cout << "Cloning complete." << endl;
	bool failed = false;
	int numtests = 10000;
	cout << "Running " << numtests << " trial(s) to compare twisters..." << endl;
	for (int i = 0; i < numtests; i++) {
		if (clonedRand.m_rand() != rand.m_rand()) {
			failed = true;
			cout << "Exited at trial " << i << endl;
		}
	}
	cout << "Clone of MT19937: " << (failed ? "failed" : "succeeded") << endl;
}

void Set3Challenge24() {

	// Part 1. Test encryption and decryption using a stream cipher generated via MT19937
	cout << "Part 1: Test encryption and decryption using MT19937-derived keystream." << endl;
	ByteVector testPlaintext = ByteVector("I am the very model of a modern Major-General\nI've information vegetable, animal, and mineral\nI know the kings of England, and I quote the fights historical\nFrom Marathon to Waterloo, in order categorical", ASCII);
	ByteVector testCiphertext = ByteVector(testPlaintext.length());
	uint16_t seed = (uint16_t)ByteRandom::rand_range(0, 65535);
	ByteEncryption::mt19937_stream_encrypt(&testPlaintext, seed, &testCiphertext);
	cout << "Testing stream enciphered with MT19937 keystream: " << endl;
	cout << testCiphertext.toStr(ASCII) << endl;
	ByteVector testDecryption = ByteVector(testCiphertext.length());
	ByteEncryption::mt19937_stream_encrypt(&testCiphertext, seed, &testDecryption);
	cout << "Testing decryption:" << endl;
	cout << testDecryption.toStr(ASCII) << endl;

	// Part 2. Determine 16 bit seed used to encrypt partially known plaintext.
	cout << endl << "Part 2: Recover 16-bit seed from MT19937 keystream using partially known plaintext." << endl;
	size_t secretRandomPrefixLen = ByteRandom::rand_range(10, 1000);
	// plaintext is a prefix of random characters + 14 'A's.
	ByteVector secretPlainText = ByteVector(secretRandomPrefixLen + 14);
	for (size_t i = 0; i < secretRandomPrefixLen; i++) {
		secretPlainText.setAtIndex((byte)ByteRandom::rand_range(0, 255), i);
	}
	for (size_t i = secretRandomPrefixLen; i < secretRandomPrefixLen + 14; i++) {
		secretPlainText.setAtIndex((byte)'A', i);
	}
	ByteVector encryption = ByteVector(secretPlainText.length());
	ByteEncryption::mt19937_stream_encrypt(&secretPlainText, seed, &encryption);

	// with only a 16 bit seed, we can just bruteforce this
	cout << "Testing seeds..." << endl;
	ByteVector decryption = ByteVector(secretPlainText.length());
	ByteVector comparison = ByteVector("AAAAAAAAAAAAAA", ASCII);
	bool found = false;
	for (uint32_t testSeed = 0; testSeed <= 65535; testSeed++) {
		ByteEncryption::mt19937_stream_encrypt(&encryption, (uint16_t)testSeed, &decryption);
		if (comparison.equalAtIndex(&decryption, 0, comparison.length(), decryption.length() - comparison.length())) {
			cout << "Found decrypting seed at " << testSeed << endl;
			cout << "Actual seed is " << seed << endl;
			found = true;
			break;
		}
	}
	if (!found) {
		cout << "Unable to locate decrypting seed." << endl;
	}

	// Part 3. Password reset token testing.
	// I'm taking it as given that we know approximate seed (i.e. the current epoch). We need to determine if
	// a given sequence of bytes could be produced by MT19937 using that seed.
	// MT19937 has a period of 2^19937-1, so exhaustive testing would be impractical.
	// I guess we just take as given that the token will be generated by a newly initialized twister?
	// The challenge wording isn't very specific.

	cout << endl << "Part 3: Test whether a token of random bytes was generated by MT19937 seeded with current time." << endl;

	size_t token_length = 16;
	std::time_t now = std::time(nullptr);
	ByteVector token = ByteVector(token_length);
	ByteRandom random = ByteRandom();
	random.m_seed((int)now);
	random.m_rand_bytes(&token, token_length);

	// test token against range of possible seeds near to current epoch
	cout << "Test token " << (ByteRandom::test_token(&token, 100) ? "matches" : "does not match") << " bytes generated by MT19937 seeded with current time (match expected)" << endl;

	// test token generated with rand()
	ByteVector token2 = ByteVector(token_length);
	for (size_t i = 0; i < token_length; i++) {
		token2.setAtIndex((byte)ByteRandom::rand_range(0, 255) , i);
	}
	cout << "Test token 2 " << (ByteRandom::test_token(&token2, 100) ? "matches" : "does not match") << " bytes generated by MT19937 seeded with current time (match not expected)" << endl;

}

int Set3() {
	cout << "### SET 3 ###" << endl;
	cout << "Set 3 Challenge 17" << endl;
	Set3Challenge17();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 3 Challenge 18" << endl;
	Set3Challenge18();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 3 Challenge 19" << endl;
	Set3Challenge19();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 3 Challenge 20" << endl;
	Set3Challenge20();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 3 Challenge 21" << endl;
	Set3Challenge21();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 3 Challenge 22" << endl;
	Set3Challenge22();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 3 Challenge 23" << endl;
	Set3Challenge23();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 3 Challenge 24" << endl;
	Set3Challenge24();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	return 0;
}