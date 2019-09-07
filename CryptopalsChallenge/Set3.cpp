#include "Set3.h"
#include "ByteVector.h"
#include "ByteEncryption.h"
#include "PlaintextEvaluator.h"
#include <iostream>
#include <fstream>
#include <string>


using namespace std;

void printAttemptedPartial(ByteVector *bv, size_t partial_index_start, size_t partial_index_end, bool ascii, size_t index) {
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

	// This is going to be trial and error, which is sort of the point of the exersise.

	// 1) Let's look for possible line starters. "The ", "the ",  "A " and "a " (include spaces)
	vector<ByteVector> initialTests;
	initialTests.push_back(ByteVector("A ", ASCII));
	initialTests.push_back(ByteVector("a ", ASCII));
	initialTests.push_back(ByteVector("The ", ASCII));
	initialTests.push_back(ByteVector("the ", ASCII));
	initialTests.push_back(ByteVector("I ", ASCII));
	initialTests.push_back(ByteVector("i ", ASCII));
	initialTests.push_back(ByteVector("This ", ASCII));
	initialTests.push_back(ByteVector("this ", ASCII));
	
	int initialTestIndex = 0;
	ByteVector keystream = ByteVector(max_keylen);
	keystream.allBytes(0);
	
	bool initialFound = false;
	size_t lockedIndex = 0;

	cout << "A set of possible line beginnings will be tested against all inputs. Keep hitting enter until you see all Latin characters appearing in the section of each line denoted by | characters." << endl;
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
				printAttemptedPartial(&temp, 0, xorBytes.length() - 1, true, j);
				// I'm thinking about a basic interactive system to
				// examine and slot in keystream bytes. TBD
			}
			cout << xorBytes.toStr(HEX) << endl;
			cout << "Press enter to continue or type lock:";
			
			string inputStr;
			//cin >> inputStr;
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
			printAttemptedPartial(&partial, 0, lockedIndex -1, true, i);
		}
		cout << "Key bytes: " << keystream.toStr(HEX) << endl;
		cout << "Enter possible next characters on a line to test them. Type 'lock' to lock in a guess. Type 'back' to remove a byte from the locked keystream:";
		string inputStr;
		//cin >> inputStr;
		getline(cin, inputStr);
		if (inputStr == "lock" || inputStr == "Lock" || inputStr == "LOCK") {
			trialKeyStream.copyBytesByIndex(&keystream, 0, keystream.length(), 0);
			//xorBytes.copyBytesByIndex(&keystream, 0, xorBytes.length(), lockedIndex);
			lockedIndex += xorBytes.length();
			trialBytes.resize(0);
			if (lockedIndex == keystream.length()) {
				decoded = true;
			}
			cout << lockedIndex << endl;
			cout << keystream.length() << endl;
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
	//Set3Challenge19();
	//// Pause before continuing
	//cout << "Press enter to continue..." << endl;
	//getchar();

	return 0;
}