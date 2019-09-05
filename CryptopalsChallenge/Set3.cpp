#include "Set3.h"
#include "ByteVector.h"
#include "ByteEncryption.h"
#include <iostream>


using namespace std;

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
	return 0;
}