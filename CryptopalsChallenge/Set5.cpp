#include "Set5.h"
#include "ByteVector.h"
#include "ByteVectorMath.h"
#include <iostream>

using namespace std;

void Set5Challenge33() {
	size_t dividend = 95;
	ByteVectorMath m5 = ByteVectorMath(dividend);
	cout << m5.toStr(BINARY) << " " << m5.uint64val() << endl;
	m5.truncateRight();
	cout << m5.toStr(BINARY) << " " << m5.uint64val() << endl;
	for (size_t i = 1; i < 100; i++) {
		ByteVectorMath a = ByteVectorMath(m5, false);
		ByteVectorMath b = ByteVectorMath(i);
		ByteVectorMath r = ByteVectorMath();
		a.divideSelf(b, &r);
		cout << i << "\t" << a.uint64val() << "\t" << r.uint64val() << "\t" << dividend / i << "\t" << dividend % i << endl;
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