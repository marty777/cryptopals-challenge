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
		float threshold = 0.8f;
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

void Set1Challenge6() {
	
	char *input1 = "this is a test";
	char *input2 = "wokka wokka!!!";
	ByteVector input1_bv = ByteVector(input1, ASCII);
	ByteVector input2_bv = ByteVector(input2, ASCII);
	cout << "Test input 1:\t" << input1_bv.toStr(ASCII) << endl;
	cout << "Test input 2:\t" << input2_bv.toStr(ASCII) << endl;
	cout << "Test hamming distance:\t" << dec << (int)input1_bv.hammingDistance(&input2_bv) << endl;

	char *filePath = "../challenge-files/set1/6.txt";
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

	// Test hamming distances of sequential blocks for various potential key lengths.
	// Lower hamming distance indicates more likely length of actual key
	const int max_keysize = 40;
	float keysize_distances[max_keysize];
	for (int i = 0; i < max_keysize; i++) {
		// let's try averaging multiple blocks per keysize
		// keysize = i+1
		size_t h1 = bv.hammingDistance(&bv, true, 0, i, i + 1, 2*i + 1);
		size_t h2 = bv.hammingDistance(&bv, true, i+1, 2*i+1, 2*i+2, 3*i+2);
		size_t h3 = bv.hammingDistance(&bv, true, 2*i + 2, 3 * i + 2, 3 * i + 3, 4 * i + 3);
		keysize_distances[i] = (float)(h1 + h2 + h3) / ((i + 1) * 3.0f);
		//cout << (i + 1) << " " << keysize_distances[i] << endl;
	}
	// ugh, sorting
	int keysize_order[max_keysize];
	int j = 0;
	while (j < max_keysize) {
		float best_distance = 1000;
		int best_index = -1;
		for (int i = 0; i < max_keysize; i++) {
			bool already_found = false;
			for (int k = 0; k < j; k++) {
				if (keysize_order[k] == i) {
					already_found = true;
					break;
				}
			}
			if (already_found) {
				continue;
			}
			if (keysize_distances[i] < best_distance) {
				best_distance = keysize_distances[i];
				best_index = i;
			}
		}
		keysize_order[j] = best_index;
		j++;
	}

	/*for (int i = 0; i < max_keysize; i++) {
		cout << (i) << " " << keysize_order[i] << endl;
	}*/

	// Test the top 5 likely keysizes

	float best_decrypt_score = 100000;
	int best_keysize = 0;
	ByteVector best_key;

	for (int i = 0; i < 5; i++) {
		int keysize = keysize_order[i] + 1;
		int numblocks = bv.length() / keysize;
		ByteVector *transpose_blocks = new ByteVector[keysize];
		ByteVector potential_key = ByteVector(keysize);
		for (int j = 0; j < keysize; j++) {
			// transpose nth byte of each keysize-sized block into a new vector
			transpose_blocks[j] = ByteVector(numblocks);
			int block = 0;
			for (int k = j; k < bv.length() - keysize; k += keysize) {
				transpose_blocks[j].setAtIndex(bv.atIndex(k), block);
				block++;
			}
			// treat transposed vector as a single-byte keyed xor cipher and test character frequencies for all bytes
			ByteVector key_bv = ByteVector(1);
			float histogram[255];
			for (byte b = 0; b < 255; b++) {
				key_bv.setAtIndex(b, 0);
				ByteVector result = transpose_blocks[j]. xor (&key_bv);
				string resultText(reinterpret_cast<char*>(result.toStr(ASCII)));
				histogram[b] = PlaintextEvaluator::score(resultText);
			}
			// record best scoring byte for this keylength and position
			byte best_byte = 0;
			float best_score = 1000;
			for (byte b = 0; b < 255; b++) {
				if (histogram[b] < best_score) {
					best_byte = b;
					best_score = histogram[b];
				}
			}
			potential_key.setAtIndex(best_byte, j);
		}
		// attempt decryption with potential key
		ByteVector decryption = bv. xor (&potential_key);
		// test character frequency
		string resultText(reinterpret_cast<char*>(decryption.toStr(ASCII)));
		float score = PlaintextEvaluator::score(resultText);
		if (score < best_decrypt_score) {
			best_decrypt_score = score;
			best_keysize = keysize;
			best_key = ByteVector(potential_key);
		}
	}
	
	cout << "Best key length:\t" << best_keysize << endl;
	cout << "Best key:\t" << best_key.toStr(HEX) << endl << "\t\t" << best_key.toStr(ASCII) << endl ;
	ByteVector decryption = bv. xor (&best_key);
	cout << "Decryption: " << endl << decryption.toStr(ASCII) << endl;

}

int main() {
	
	//cout << "Set 1 Challenge 1\n";
	//Set1Challenge1();
	//// Pause before continuing
	//cout << "Press any key to continue...\n";
	//getchar();
	//cout << "Set 1 Challenge 2\n";
	//Set1Challenge2();
	//// Pause before continuing
	//cout << "Press any key to continue...\n";
	//getchar();
	//cout << "Set 1 Challenge 3\n";
	//Set1Challenge3();
	//// Pause before continuing
	//cout << "Press any key to continue...\n";
	//getchar();
	//cout << "Set 1 Challenge 4\n";
	//Set1Challenge4();
	//// Pause before continuing
	//cout << "Press any key to continue...\n";
	//getchar();
	//cout << "Set 1 Challenge 5\n";
	//Set1Challenge5();
	//// Pause before continuing
	//cout << "Press any key to continue...\n";
	//getchar();
	cout << "Set 1 Challenge 6\n";
	Set1Challenge6();
	// Pause before continuing
	cout << "Press any key to continue...\n";
	getchar();
	return 0;
}
