#include "Set5.h"
#include "ByteVector.h"
#include "ByteVectorMath.h"
#include <iostream>

using namespace std;

void Set5Challenge33() {
	ByteVectorMath m1 = ByteVectorMath(4095);
	cout << m1.toStr(BINARY) << " " << m1.uint64val() << endl;
	for (size_t i = 100; i < 4095; i++) {
		ByteVectorMath m2 = ByteVectorMath(i);
		m1.subtractSelf(m2);
		if (m1.uint64val() != 4095 - i) {
			cout << "No match " << m1.uint64val() << " " << (4095 - i) << endl;
			break;
		}
		m1.addSelf(m2);
	}
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