#include "Set4.h"
#include "ByteVector.h"
#include "ByteEncryption.h"
#include "ByteRandom.h"
#include "Utility.h"
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
	// Test bitflipping
	ByteVector test = ByteVector(32); // 2 blocks
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

void Set4Challenge27() {
	ByteVector payload = ByteVector("THISISSOMEJUNK!!:admin<true:AAAA", ASCII);
	ByteVector output = ByteVector();
	ByteVector secretKey = ByteVector(16);
	secretKey.random();
	cout << "Passing input for encryption..." << endl;
	ByteEncryption::challenge27encrypt(&payload, &secretKey, &output);
	// zero second 16-byte block in encrypted output
	// and copy block 0 to block 2
	cout << "Modifying encrypted message blocks..." << endl;
	for (size_t i = 0; i < 16; i++) {
		output.setAtIndex(0, i+16);
		output.setAtIndex(output.atIndex(i), i + 32);
	}
	cout << "Passing modified encrypted message for decryption..." << endl;
	ByteEncryptionError err;
	ByteEncryption::challenge27decrypt(&output, &secretKey, &err);
	if (err.hasErr()) {
		cout << "Decryption returns error message." << endl;
		ByteVector vec = ByteVector((char *)err.message.c_str(), ASCII);
		vec.printASCIIStrByBlocks(16);
		size_t offset = strlen("Noncompliant values: ");
		ByteVector extraction = ByteVector(vec.length() - offset);
		for (size_t i = 0; i < extraction.length(); i++) {
			extraction.setAtIndex(vec.atIndex(i + offset), i);
		}
		ByteVector extractedKey = ByteVector(16);
		for (size_t i = 0; i < 16; i++) {
			extractedKey.setAtIndex(extraction.atIndex(i) ^ extraction.atIndex(i + 32) , i);
		}
		cout << "Recovered key:\t" << extractedKey.toStr(HEX) << endl;
		cout << "Original key:\t" << secretKey.toStr(HEX) << endl;
		cout << "Recovered key " << (extractedKey.equal(&secretKey) ? "matches" : "does not match") << " original key." << endl;
	}
}

void Set4Challenge28() {
	ByteVector message = ByteVector("The quick brown fox jumps over the lazy dog", ASCII);
	cout << "Original message: " << message.toStr(ASCII) << endl;
	ByteVector key = ByteVector("YELLOW SUBMARINE", ASCII);
	cout << "Original key: " << key.toStr(ASCII) << endl;
	
	ByteVector mac = ByteVector();
	ByteEncryption::sha1_MAC(&message, &key, &mac);
	cout << "MAC of message: " << mac.toStr(HEX) << endl;
	
	cout << "Tampering with message..." << endl;
	ByteVector message2 = ByteVector("The quick brown fox jumps over the lazy cog", ASCII);
	ByteVector mac2 = ByteVector();
	ByteEncryption::sha1_MAC(&message2, &key, &mac2);
	cout << "Tampered message MAC " << (mac2.equal(&mac) ? "matches" : "does not match") << " original MAC:" << mac2.toStr(HEX) << endl;

	cout << "Testing MAC without knowing key..." << endl;
	ByteVector key2 = ByteVector(16);
	key2.allBytes(0);
	ByteVector mac3 = ByteVector();
	ByteEncryption::sha1_MAC(&message, &key2, &mac3);
	cout << "MAC with differing key " << (mac3.equal(&mac) ? "matches" : "does not match") << " original MAC: " << mac3.toStr(HEX) << endl;
}

void Set4Challenge29() {
	// random secret key of random length
	ByteVector secretKey = ByteVector(rand_range(32,256));
	secretKey.random();
	ByteVector input = ByteVector("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon", ASCII);
	
	ByteVector initialMAC = ByteVector();
	ByteEncryption::sha1_MAC(&input, &secretKey, &initialMAC);
	
	cout << "Initial MAC" << endl;
	initialMAC.printHexStrByBlocks(20);

	ByteVector payload = ByteVector(";admin=true", ASCII);

	// forge a MAC for our payload
	uint32_t state0 = (((uint32_t)initialMAC[0]) << 24) | (((uint32_t)initialMAC[1]) << 16) | (((uint32_t)initialMAC[2]) << 8) | (((uint32_t)initialMAC[3]));
	uint32_t state1 = (((uint32_t)initialMAC[4]) << 24) | (((uint32_t)initialMAC[5]) << 16) | (((uint32_t)initialMAC[6]) << 8) | (((uint32_t)initialMAC[7]));
	uint32_t state2 = (((uint32_t)initialMAC[8]) << 24) | (((uint32_t)initialMAC[9]) << 16) | (((uint32_t)initialMAC[10]) << 8) | (((uint32_t)initialMAC[11]));
	uint32_t state3 = (((uint32_t)initialMAC[12]) << 24) | (((uint32_t)initialMAC[13]) << 16) | (((uint32_t)initialMAC[14]) << 8) | (((uint32_t)initialMAC[15]));
	uint32_t state4 = (((uint32_t)initialMAC[16]) << 24) | (((uint32_t)initialMAC[17]) << 16) | (((uint32_t)initialMAC[18]) << 8) | (((uint32_t)initialMAC[19]));

	// need to determine how the padding is set up so we get
	// sha1(key + input + initial padding + initial length of key + input (8 bytes) + payload + padding + final length (8 bytes)
	// the key length is unknown, so we need to guess.
	
	// keylen is possible key size in bytes
	for (size_t keylen = 20; keylen < 512; keylen++) {
		size_t first_section_len = input.length() + keylen;
		size_t first_section_padded_len = first_section_len + 1;
		size_t first_section_total_len = first_section_padded_len + (64 - first_section_padded_len % 64);
		if (first_section_total_len % 64 > 56) {
			first_section_total_len += 64;
		}

		ByteVector len64 = ByteVector(8);
		len64[0] = (byte)(0xff & (first_section_len * 8) >> 56);
		len64[1] = (byte)(0xff & (first_section_len * 8) >> 48);
		len64[2] = (byte)(0xff & (first_section_len * 8) >> 40);
		len64[3] = (byte)(0xff & (first_section_len * 8) >> 32);
		len64[4] = (byte)(0xff & (first_section_len * 8) >> 24);
		len64[5] = (byte)(0xff & (first_section_len * 8) >> 16);
		len64[6] = (byte)(0xff & (first_section_len * 8) >> 8);
		len64[7] = (byte)(0xff & (first_section_len * 8));

		// if correct keylen, key + input + 0x80 + padding + len64 should align on a block boundary
		// and sha1_from_starting_state(mac_of_above, payload) should equal mac under secret key of key + input + 0x80 + padding + len64 + payload

		ByteVector trialinput = ByteVector(first_section_total_len - keylen + payload.length());
		trialinput.allBytes(0);
		input.copyBytesByIndex(&trialinput, 0, input.length(), 0);
		trialinput[input.length()] = 0x80;
		len64.copyBytesByIndex(&trialinput, 0, len64.length(), first_section_total_len - keylen - 8);
		payload.copyBytesByIndex(&trialinput, 0, payload.length(), first_section_total_len - keylen);

		ByteVector trialMAC = ByteVector();
		ByteEncryption::sha1_MAC(&trialinput, &secretKey, &trialMAC);


		ByteVector forgedMAC = ByteVector();
		ByteEncryption::sha1(&payload, &forgedMAC, first_section_total_len, state0, state1, state2, state3, state4);
		
		if (trialMAC.equal(&forgedMAC)) {
			cout << "Found match at trial key length " << keylen << endl;
			cout << "Forged input bytes (ASCII) are: " << endl;
			trialinput.printASCIIStrByBlocks(16);
			cout << "Forged MAC hash from initial MAC:" << endl;
			forgedMAC.printHexStrByBlocks(20);
			cout << "Test MAC hash of forged input bytes:" << endl;
			trialMAC.printHexStrByBlocks(20);
			break;
		}

	}
}

void Set4Challenge30() {
	ByteVector test1 = ByteVector("The quick brown fox jumps over the lazy dog", ASCII);
	ByteVector expected1 = ByteVector("1bee69a46ba811185c194762abaeae90", HEX);
	ByteVector test2 = ByteVector("The quick brown fox jumps over the lazy cog", ASCII);
	ByteVector expected2 = ByteVector("b86e130ce7028da59e672d56ad0113df", HEX);
	ByteVector test3 = ByteVector("", ASCII);
	ByteVector expected3 = ByteVector("31d6cfe0d16ae931b73c59d7e0c089c0", HEX);

	ByteVector test4 = ByteVector("Rosetta Code", ASCII);

	ByteVector output = ByteVector();

	cout << "Testing " << test1.toStr(ASCII) << endl;
	ByteEncryption::md4(&test1, &output);
	cout << "Output:   ";
	output.printHexStrByBlocks(16);
	cout << "Expected: ";
	expected1.printHexStrByBlocks(16);

	cout << "Testing " << test2.toStr(ASCII) << endl;
	ByteEncryption::md4(&test2, &output);
	cout << "Output:   ";
	output.printHexStrByBlocks(16);
	cout << "Expected: ";
	expected2.printHexStrByBlocks(16);

	cout << "Testing empty string" << endl;
	ByteEncryption::md4(&test3, &output);
	cout << "Output:   ";
	output.printHexStrByBlocks(16);
	cout << "Expected: ";
	expected3.printHexStrByBlocks(16);

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
	cout << "Set 4 Challenge 27" << endl;
	Set4Challenge27();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 4 Challenge 28" << endl;
	Set4Challenge28();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 4 Challenge 29" << endl;
	Set4Challenge29();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
}