#include "Set5.h"
#include "ByteVector.h"
#include <iostream>

using namespace std;

void Set5Challenge33() {
	ByteVector a = ByteVector("00111100", BINARY);
	ByteVector b = ByteVector("00001101", BINARY);
	cout << "A:\t" << a.toStr(BINARY) << endl;
	cout << "B:\t" << b.toStr(BINARY) << endl;
	
	ByteVector c = a & b;
	cout << "A&B:\t" << c.toStr(BINARY) << endl;
	ByteVector d = a | b;
	cout << "A|B:\t" << d.toStr(BINARY) << endl;
	ByteVector e = a ^ b;
	cout << "A^B:\t" << e.toStr(BINARY) << endl;

	ByteVector f = ~a;
	cout << "~A:\t" << f.toStr(BINARY) << endl;
}

int Set5() {
	cout << "### SET 5 ###" << endl;
	cout << "Set 5 Challenge 33" << endl;
	Set5Challenge33();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
}