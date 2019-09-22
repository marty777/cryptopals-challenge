#include "Set4.h"
#include "ByteVector.h"
#include "ByteEncryption.h"
#include "ByteRandom.h"
#include <iostream>
#include <fstream>

using namespace std;

void Set4Challenge25() {
	char *filePath = "../challenge-files/set4/25.txt";
	ifstream f;
	string input;

	f.open(filePath);
	f.seekg(0, std::ios::end);
	input.reserve(f.tellg());
	f.seekg(0, std::ios::beg);

	input.assign((std::istreambuf_iterator<char>(f)),
		std::istreambuf_iterator<char>());

	f.close();

	// A bit oblique in the instructions, but this is the same file as challenge 7. It's AES-128 ECB encrypted using the key "YELLOW SUBMARINE"
	ByteVector bv = ByteVector(&input[0], BASE64);
	ByteVector key = ByteVector("YELLOW SUBMARINE", ASCII);
	ByteVector decrypted = ByteVector(bv.length());
	cout << "Decrypting input file in AES ECB mode with key '" << key.toStr(ASCII) << "'..." << endl;
	ByteEncryption::aes_ecb_encrypt(&bv, &key, &decrypted, 0, bv.length() - 1, false);

	// encrypt in CTR mode using a secret key and nonce.
	ByteRandom random = ByteRandom();
	ByteVector secretKey = ByteVector(16);
	secretKey.random();
	unsigned long long secretNonce = rand();
	ByteVector encrypted = ByteVector(decrypted.length());
	cout << "Encrypting in CTR mode with random secret key and nonce..." << endl;
	ByteEncryption::aes_ctr_encrypt(&decrypted, &secretKey, &encrypted, secretNonce);

	// With encrypted text known and an aes_ctr_edit function exposed, obtain the CTR keystream and 
	// use it to decrypt the original text
	ByteVector editText = ByteVector(encrypted.length());
	ByteVector encryptedCopy = ByteVector(encrypted);
	editText.allBytes(0);
	cout << "Obtaining keystream from exposed edit function..." << endl;
	ByteEncryption::aes_ctr_edit(&encryptedCopy, &secretKey, secretNonce, 0, &editText);
	// encrypted copy should be the keystream XORd with all 0 bytes = the keystream
	ByteVector output = ByteVector(encrypted.length());
	for (size_t i = 0; i < output.length(); i++) {
		output.setAtIndex(encrypted.atIndex(i) ^ encryptedCopy.atIndex(i), i);
	}

	cout << "Recovered plaintext:" << endl;
	cout << output.toStr(ASCII) << endl;
}

void Set4Challenge26() {
	// Test bitflipping - Yikes. This is both vulurable to easy replacement of known plaintext even in
	// the first block, and I think you can recover unknown plaintext if you can compare flipped and 
	// unflipped decryptions (several times?)
	ByteVector test = ByteVector(256); // 16 blocks
	for (size_t i = 0; i < test.length(); i++) {
		test.setAtIndex((byte)i, i);
	}
	cout << "Bitflipping test input for CTR stream: " << endl;
	test.printHexStrByBlocks(16);
	ByteVector testKey = ByteVector(16);
	testKey.random();
	unsigned long long testNonce = rand();
	ByteVector testEncrypt = ByteVector(test.length());
	ByteVector testDecrypt = ByteVector(test.length());
	ByteEncryption::aes_ctr_encrypt(&test, &testKey, &testEncrypt, testNonce);
	cout << "Flipping bits to inject 0x" <<std::hex << 0xc0ffeedecade << std::dec << endl;
	testEncrypt.setAtIndex(testEncrypt.atIndex(0) ^ (0x00 ^ 0xc0), 0);
	testEncrypt.setAtIndex(testEncrypt.atIndex(1) ^ (0x01 ^ 0xff), 1);
	testEncrypt.setAtIndex(testEncrypt.atIndex(2) ^ (0x02 ^ 0xee), 2);
	testEncrypt.setAtIndex(testEncrypt.atIndex(3) ^ (0x03 ^ 0xde), 3);
	testEncrypt.setAtIndex(testEncrypt.atIndex(4) ^ (0x04 ^ 0xca), 4);
	testEncrypt.setAtIndex(testEncrypt.atIndex(5) ^ (0x05 ^ 0xde), 5);
	ByteEncryption::aes_ctr_encrypt(&testEncrypt, &testKey, &testDecrypt, testNonce);
	cout << "Bitflipped decryption:" << endl;
	testDecrypt.printHexStrByBlocks(16);

	cout << "Attempting bitflipping to inject admin credentials...";
	ByteVector payload = ByteVector("THISISSOMEJUNK!!:admin<true:AAAA", ASCII);
	ByteVector output = ByteVector();
	ByteVector secretKey = ByteVector(16);
	unsigned long long secretNonce = rand();
	secretKey.random();
	ByteEncryption::challenge26encrypt(&payload, &secretKey, &output, secretNonce);
	// flip some bits - assume we don't know the position of our payload in the encrypted string
	bool found = false;
	for (size_t i = 0; i < output.length() - 11; i++) {
		ByteVector modifiedOutput = ByteVector(output);
		modifiedOutput.setAtIndex(output.atIndex(i + 0) ^ 0x01, i + 0);
		modifiedOutput.setAtIndex(output.atIndex(i + 6) ^ 0x01, i + 6);
		modifiedOutput.setAtIndex(output.atIndex(i + 11) ^ 0x01, i + 11);
		if (ByteEncryption::challenge26decrypt(&modifiedOutput, &secretKey, secretNonce)) {
			found = true;
			break;
		}
	}
	cout << (found ? "Success" : "Failure") << endl;
}

int Set4() {
	cout << "### SET 4 ###" << endl;
	cout << "Set 4 Challenge 25" << endl;
	Set4Challenge25();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	cout << "Set 4 Challenge 26" << endl;
	Set4Challenge26();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
}