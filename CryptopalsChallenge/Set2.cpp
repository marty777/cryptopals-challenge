#include "ByteVector.h"
#include "ByteEncryption.h"
#include "PlaintextEvaluator.h"
#include "KeyValueParser.h"
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

void Set2Challenge13() {
	string user_role = "user";
	string admin_role = "admin";
	KeyValueParser parser = KeyValueParser();
	ByteVector email = ByteVector("foo@bar.com", ASCII);
	ByteVector outputProfile = ByteVector();
	// Test parser
	parser.profile_for(&email, &outputProfile);
	cout << "Profile parser test:\t" << outputProfile.toStr(ASCII) << endl;

	// random 128-bit AES key
	ByteVector key = ByteVector(16);
	key.random();

	// Test oracle profile_for and parsing decryption
	ByteVector encryptedProfile = ByteVector();
	parser.encrypt_profile_for(&email, &key, &encryptedProfile);
	
	parser.decrypt_profile_for(&encryptedProfile, &key);
	cout << "Test profile decrypted role:\t" << parser.valueWithKey("role") << endl;

	// For completeness, determine blocksize
	ByteVector input = ByteVector();
	size_t len = 0;
	size_t last_len = 0;
	size_t block_size = 0;
	for (size_t i = 0; i < 255; i++) {
		input.resize(i);
		parser.encrypt_profile_for(&input, &key, &encryptedProfile);
		len = encryptedProfile.length();
		if (last_len != 0 && len != last_len) {
			block_size = len - last_len;
		}
		last_len = len;
	}
	cout << "Detected block size:\t" << block_size << endl;
	// Not going to bother checking for ECB vs CBC right now.

	// So, we need to figure out a ciphertext that includes role=admin
	// My function won't work well with multiple values on the same key, so we can't just stick it on the end.
	// The parsing of the delimiter characters on the input prevents directly inserting "&role=admin" into the ciphertext.

	// if we can push out in input to force the 'admin' part of role=admin to a separate block...
	// Ah: Pad the input so that we get 0x000000...|admin00000...|rest of profile|
	// I'm assuming that I know that blocks are padded with 0s. We don't necessarily know how long the field names
	// or delimters are, so some searching will be required.

	// first -> get ciphertext that isolates 'user' in the final block. Assume we know that's the value.

	// Test input lengths until we can find the right length to isolate the role value
	len = 0;
	last_len = 0;
	size_t isolated_len = 0;
	ByteVector userEncryptedBlock = ByteVector(block_size);
	for (size_t i = 0; i < block_size; i++) {
		input.resize(i);
		parser.encrypt_profile_for(&input, &key, &encryptedProfile);
		len = encryptedProfile.length();
		if (last_len != 0 && len != last_len) {
			// we've nudged 1 character over the blocksize
			isolated_len = i - 1 + user_role.length();
			break;
		}
		last_len = len;
	}
	input.resize(isolated_len);
	parser.encrypt_profile_for(&input, &key, &encryptedProfile);
	// copy last encrypted block
	size_t roleBlockIndex = encryptedProfile.length() / block_size; // index of last block
	for (size_t i = 0; i < block_size; i++) {
		encryptedProfile.copyBytesByIndex(&userEncryptedBlock, encryptedProfile.length() - block_size, block_size, 0);
	}
	
	// Now, set the input to isolate |admin00000...| in a single block
	// I fiddled around with a more complicated search for right prefix length on the input, but we can 
	// try this with |user000...| as the payload and wait until we get a match with the block we isolated
	// above

	ByteVector payloadUser = ByteVector("user", ASCII);
	ByteVector payloadAdmin = ByteVector("admin", ASCII);
	payloadUser.padToLength(block_size, 0);
	payloadAdmin.padToLength(block_size, 0);
	ByteVector testInput = ByteVector();
	ByteVector testOutput = ByteVector();
	ByteVector adminEncryptedBlock = ByteVector(block_size);
	size_t prefix_len = 0;
	for (size_t i = 0; i < block_size; i++) {
		testInput.resize(i + payloadUser.length());
		for (size_t j = 0; j < i; j++) {
			testInput.setAtIndex('A', j);
		}
		// copy in the payload to the appropriate position
		for (size_t j = 0; j < block_size; j++) {
			testInput.setAtIndex(payloadUser.atIndex(j), i + j);
		}
		// encrypt with the test input
		parser.encrypt_profile_for(&testInput, &key, &testOutput);

		// check to see if we have a block that matches our userEncryptedBlock. It won't 
		// be the first or last block
		bool found = false;
		size_t block_index = 0;
		for (size_t j = 1; j < (testOutput.length() / block_size) - 1; j++) {
			if (userEncryptedBlock.equalAtIndex(&testOutput, 0, block_size, j*block_size)) {
				found = true;
				block_index = j;
				break;
			}
		}
		if (found) {
			prefix_len = i;

			// update with admin payload
			for (size_t j = 0; j < block_size; j++) {
				testInput.setAtIndex(payloadAdmin.atIndex(j), i + j);
			}

			// re-encrypt
			parser.encrypt_profile_for(&testInput, &key, &testOutput);
			
			// copy encrypted admin block
			testOutput.copyBytesByIndex(&adminEncryptedBlock, block_index * block_size, block_size, 0);
			
			// copy admin block a new encrypted profile with the correct length of input and see if it works
			ByteVector finalInput = ByteVector(isolated_len);
			for (size_t j = 0; j < isolated_len; j++) {
				finalInput.setAtIndex('A', j); // not really an email address, but I know it's not being checked.
			}
			ByteVector finalEncryptedProfile = ByteVector();
			parser.encrypt_profile_for(&finalInput, &key, &finalEncryptedProfile);

			adminEncryptedBlock.copyBytesByIndex(&finalEncryptedProfile, 0, block_size, ((finalEncryptedProfile.length() / block_size) - 1) * block_size);
			parser.decrypt_profile_for(&finalEncryptedProfile, &key);
			cout << (parser.valueWithKey("role") == "admin" ? "Success" : "Failure") << endl;
			cout << "email:\t" << parser.valueWithKey("email") << endl;
			cout << "uid:\t" << parser.valueWithKey("uid") << endl;
			cout << "role:\t" << parser.valueWithKey("role") << endl;
		}
	}
	
}

void Set2Challenge14() {

	size_t block_size = 16; // I'm taking this as a given. I know how to determine block size for this challenge.
	ByteVector post = ByteVector("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK", BASE64);
	ByteVector secretKey = ByteVector(16);
	secretKey.random();
	// I initially read this part of the challenge to mean a different random prefix applied to each oracle query. That sounds harder.
	ByteVector pre = ByteVector(rand() % 257);
	pre.random();
	
	ByteVector output = ByteVector();
	// Determine input offset to push one byte of target bytes to next block.
	ByteVector input = ByteVector(2 * block_size);
	size_t zero_offset_post = 0; // input length that puts target bytes flush with end of a block.
	size_t unknown_byte_len = 0; // can't infer length of pre and post separately yet, but can get pre + post
	size_t len = 0;
	size_t last_len = 0;
	for (size_t i = 0; i < block_size+1; i++) {
		input.resize(i);
		ByteEncryption::aes_prepend_append_encrypt(&pre, &input, &post, &secretKey, &output, false);
		len = output.length();
		if (last_len > 0 && len != last_len) {
			zero_offset_post = input.length() - 1;
			unknown_byte_len = last_len - zero_offset_post;
			break;
		}
		last_len = len;
	}
	// Determine length of pre and post bytes
	input.resize(block_size + 1);
	input.allBytes(0);
	// get the initial output
	ByteEncryption::aes_prepend_append_encrypt(&pre, &input, &post, &secretKey, &output, false);
	ByteVector testOutput = ByteVector();
	size_t first_input_block_index = 0;
	size_t prev_differing_block_index = 0;
	size_t first_input_offset = 0;

	for (size_t i = 0; i < input.length(); i++) {
		// modify one byte at a time on the input until the index of the first differing block between initial output and test output
		// differ
		if (i > 0) {
			input.setAtIndex(0x0, i - 1);
		}
 		input.setAtIndex(0xff, i);
		ByteEncryption::aes_prepend_append_encrypt(&pre, &input, &post, &secretKey, &testOutput, false);
		size_t first_differing_block_index = 0;
		
		for (size_t j = 0; j < testOutput.length() / block_size; j++) {
			if (!testOutput.equalAtIndex(&output, block_size * j, block_size, block_size * j)) {
				first_differing_block_index = j;
				break; 
			}
		}
		if (prev_differing_block_index > 0 && first_differing_block_index != prev_differing_block_index) {
			first_input_block_index = first_differing_block_index;
			first_input_offset = i;
			break;
		}
		prev_differing_block_index = first_differing_block_index;
	}

	size_t pre_len = first_input_block_index * block_size - first_input_offset;
	size_t target_len = unknown_byte_len - pre_len;
	cout << "Prepended bytes inferred length:\t\t" << pre_len << endl;
	cout << "Appended (target) bytes inferred length:\t" << target_len << endl;

	// Decoded will produce the target bytes in non-reversed order, so we insert starting from the end.
	ByteVector decoded = ByteVector(target_len);
	decoded.allBytes(0);

	// byte-by-byte decoding from the end of the target bytes.
	// 256 blocks are inserted into the input for comparison with 
	// the byte currently being examined, plus the appropriate offsets to 
	// align the input and target blocks correctly.
	ByteVector referenceBlock = ByteVector(block_size);
	ByteVector examineBlock = ByteVector(block_size);
	for (size_t i = 0 ; i < target_len ; i++) {
		size_t input_len = first_input_offset + (256 * block_size);
		// align target bytes to end of block with additional padding
		input_len += (zero_offset_post - first_input_offset) % block_size;
		// push i % block_size bytes into next block
		input_len += (i + 1 % block_size);
		input.resize(input_len);
		// fill in the test blocks on the input with previously decoded bytes		
		referenceBlock.allBytes(0);
		// it turns out I'm really bad at thinking about indexing in two different
		// directions, so doing this carefully.
		size_t decoded_start, decoded_end;
		if (i < block_size - 1) {
			decoded_end = decoded.length() - 1;
			decoded_start = decoded_end - i;
		}
		else {
			decoded_start = decoded.length() - 1 - i;
			decoded_end = decoded_start + block_size - 1;
		}

		for (size_t j = decoded_start; j <= decoded_end; j++) {
			referenceBlock.setAtIndex(decoded.atIndex(j), j - decoded_start);
		}

		// set reference block at each test location with different test byte
		for (int j = 0; j <= 0xff; j++) {
			referenceBlock.setAtIndex((byte)j, 0);
			referenceBlock.copyBytesByIndex(&input, 0, block_size, (j * block_size) + first_input_offset);
		}

		// query the oracle
		ByteEncryption::aes_prepend_append_encrypt(&pre, &input, &post, &secretKey, &output, false);
		size_t block_index = ((output.length() - 1 - i) / 16); // index of block being currently examined in output
		output.copyBytesByIndex(&examineBlock, (block_index * block_size), block_size, 0);
		for (size_t j = 0; j <= 0xff; j++) {
			// each block encrypting the test for the next decoded byte
			output.copyBytesByIndex(&referenceBlock, (j*block_size) + first_input_offset + pre_len, block_size, 0); 
			if (referenceBlock.equal(&examineBlock)) {
				decoded.setAtIndex(j, decoded.length() - i - 1);
			}
		}

	}
	cout << "Decoded target bytes:" << endl << decoded.toStr(ASCII) << endl;

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
	cout << "Set 2 Challenge 13" << endl;
	Set2Challenge13();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 2 Challenge 14" << endl;
	Set2Challenge14();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	return 0;
}