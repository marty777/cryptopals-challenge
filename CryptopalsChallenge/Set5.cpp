#include "Set5.h"
#include "ByteVector.h"
#include "ByteVectorMath.h"
#include <iostream>

using namespace std;

void Set5Challenge33() {
	ByteVectorMath m1 = ByteVectorMath(4095);
	m1.printHexStrByBlocks(4);
	ByteVectorMath m2 = ByteVectorMath(1354682);
	cout << m1.toStr(HEX) << " " << m1.uint64val() << endl;
	cout << m2.toStr(HEX) << " " << m2.uint64val() << endl;
	m1.multiplySelf(m2);
	cout << m1.toStr(HEX) << " " << m1.uint64val() << " " << m1.length() << endl;

	cout << "Complete" << endl;
}

int Set5() {
	cout << "### SET 5 ###" << endl;
	cout << "Set 5 Challenge 33" << endl;
	Set5Challenge33();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
}