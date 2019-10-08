#include "Set5.h"
#include "ByteVector.h"
#include "ByteVectorMath.h"
#include <iostream>

using namespace std;

void Set5Challenge33() {
	ByteVectorMath m1 = ByteVectorMath(4095);
	m1.printHexStrByBlocks(16);
	//ByteVectorMath m2 = ByteVectorMath(ByteVector("10", HEX));
	cout << m1.toStr(BINARY) << " " << m1.uint64val() << endl;
	m1.rightShiftSelf(3);
	cout << m1.toStr(HEX) << " " << m1.uint64val() << endl;
	m1.rightShiftSelf(9);
	cout << m1.toStr(HEX) << " " << m1.uint64val() << endl;
	m1.printHexStrByBlocks(16);
	m1.leftShiftSelf(1);
	m1.printHexStrByBlocks(16);
	m1.leftShiftSelf(11);
	m1.printHexStrByBlocks(16);
	//m1.leftShiftSelf(5);
	//cout << m1.toStr(BINARY) << " " << m1.uint64val() << endl;
	//m1.rightShiftSelf(5);
	//cout << m1.toStr(BINARY) << " " << m1.uint64val() << endl;
	//m1.rightShiftSelf(9);
	//cout << m1.toStr(BINARY) << " " << m1.uint64val() << endl;

	
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