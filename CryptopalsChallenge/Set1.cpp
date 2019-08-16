#include "ByteVector.h"
#include <iostream>
using namespace std;


void Set1Challenge1() {
	char *inputStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	cout << "Input (hex): " << inputStr << "\n";
	ByteVector bv = ByteVector(inputStr, HEX);


}

int main() {
	char c;
	Set1Challenge1();
	// Pause before exiting
	cout << "Press any key to continue...\n";
	getchar();
	return 0;
}
