#include "ByteVector.h"
#include "PlaintextEvaluator.h"
#include <iostream>

using namespace std;

void Set2Challenge1() {
	char * input = "YELLOW SUBMARINE";
	char * expectedOutput = "YELLOW SUBMARINE\x04\x04\x04\x04";
	ByteVector bv = ByteVector(input, ASCII);
	ByteVector expectedBv = ByteVector(expectedOutput, ASCII);
	bv.padToLength(20, 0x04);
	cout << bv.toStr(ASCII) << endl;
	cout << (bv.equal(&expectedBv) ? "Output matches expected result\n" : "Output does not match expected") << endl;	
}


int Set2() {
	cout << "### SET 2 ###" << endl;
	cout << "Set 2 Challenge 1" << endl;
	Set2Challenge1();
	// Pause before continuing
	cout << "Press any key to continue..." << endl;
	getchar();
	return 0;
}