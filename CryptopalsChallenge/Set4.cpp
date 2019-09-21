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

	cout << "Recoved plaintext:" << endl;
	cout << output.toStr(ASCII) << endl;

}

int Set4() {
	cout << "### SET 4 ###" << endl;
	cout << "Set 4 Challenge 25" << endl;
	Set4Challenge25();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
}