#include "Set5.h"
#include "ByteVector.h"
#include "ByteVectorMath.h"
#include <iostream>

using namespace std;

void Set5Challenge33() {
	ByteVectorMath m1 = ByteVectorMath(1023);
	m1.printHexStrByBlocks(4);
	ByteVectorMath m2 = ByteVectorMath(2);
	cout << m1.toStr(HEX) << " " << m1.uint64val() << endl;
	cout << m2.toStr(HEX) << " " << m2.uint64val() << endl;
	m1.exponentSelf(3);
	cout << m1.toStr(HEX) << " " << m1.uint64val() << " " << m1.length() << endl;

	ByteVectorMath m3 = ByteVectorMath(3);
	ByteVectorMath m4 = ByteVectorMath(4);

	cout << "M1 < M2 " << (m1 < m2 ? "true" : "false") << endl;
	cout << "M1 == M2 " << (m1 == m2 ? "true" : "false") << endl;
	cout << "M1 > M2 " << (m1 > m2 ? "true" : "false") << endl;

	cout << "M2 < M3 " << (m2 < m3 ? "true" : "false") << endl;
	cout << "M2 == M3 " << (m2 == m3 ? "true" : "false") << endl;
	cout << "M2 > M3 " << (m2 > m3 ? "true" : "false") << endl;

	cout << "M2 < M4 " << (m2 < m4 ? "true" : "false") << endl;
	cout << "M2 == M4 " << (m2 == m4 ? "true" : "false") << endl;
	cout << "M2 > M4 " << (m2 > m4 ? "true" : "false") << endl;

	cout << "M4 < M3 " << (m4 < m3 ? "true" : "false") << endl;
	cout << "M4 == M3 " << (m4 == m3 ? "true" : "false") << endl;
	cout << "M4 > M3 " << (m4 > m3 ? "true" : "false") << endl;
	
	cout << "M1 == M1 " << (m1 == m1 ? "true" : "false") << endl;
	cout << "M2 == M2 " << (m2 == m2 ? "true" : "false") << endl;
	cout << "M3 == M3 " << (m3 == m3 ? "true" : "false") << endl;
	cout << "M4 == M4 " << (m4 == m4 ? "true" : "false") << endl;

	cout << "M1:" << m1.toStr(BINARY) << endl;
	cout << "M2:" << m2.toStr(BINARY) << endl;
	cout << "M3:" << m3.toStr(BINARY) << endl;
	cout << "M4:" << m4.toStr(BINARY) << endl;

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