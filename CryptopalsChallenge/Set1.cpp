#include "ByteVector.h"
#include <iostream>
using namespace std;


void Set1Challenge1() {
	//char *inputStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	//char *inputStr = "f013";
	char *inputStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	char *expectedOutput = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
	cout << "Input (hex): " << inputStr << "\n";
	ByteVector bv = ByteVector(inputStr, HEX);
	ByteVector bv2 = ByteVector(expectedOutput, BASE64);
	char *output = bv.toStr(BASE64);
	cout << output << "\n";
	cout << (bv.equal(&bv2) ? "Output matches expected result\n" : "Output does not match expected") << "\n";
}

int main() {
	char c;
	Set1Challenge1();
	// Pause before continuing
	cout << "Press any key to continue...\n";
	getchar();
	return 0;
}
