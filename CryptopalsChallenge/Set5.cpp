#include "Set5.h"
#include "ByteVector.h"
#include "ByteVectorMath.h"
#include "Utility.h"
#include <iostream>

using namespace std;

void Set5Challenge33() {

	ByteVectorMath(test) = ByteVectorMath(3);
	test.exponentSelf(2);
	cout << "3^2: " << test.uint64val() << endl;
	test.exponentSelf(3);
	cout << "9^33: " << test.uint64val() << endl;
	test.exponentSelf(3);
	cout << "729 ^ 3:" << test.uint64val() << endl;

	cout << "Small values:" << endl;
	srand(1000);
	ByteVectorMath p = ByteVectorMath(37);
	ByteVectorMath g = ByteVectorMath(5);
	int a = rand_range(0, 36); // rand() % 37
	printf("%d\n", a);
	ByteVectorMath A = ByteVectorMath(g, false);
	A.modExpSelf(a, p.uint64val());
	cout << "A = (g**a)%p: " << A.uint64val() << endl;
	int b = rand_range(0, 36); // rand() % 37
	ByteVectorMath B = ByteVectorMath(g, false);
	B.modExpSelf(b, p.uint64val());
	cout << "B = (g**b)%p: " << B.uint64val() << endl;

	uint32_t A_test = ((int)floor(pow(5.0, (double)a))) % 37;
	uint32_t B_test = ((int)floor(pow(5.0, (double)b))) % 37;
	cout << "Compare with 32-bit math A:" << A_test << " B:" << B_test << endl;
	
	ByteVectorMath s_B = ByteVectorMath(B, false);
	s_B.modExpSelf(a, 37);
	cout << "s = (B**a)%37: " << s_B.uint64val() << endl;
	ByteVectorMath s_A = ByteVectorMath(A, false);
	s_A.modExpSelf(b, 37);
	cout << "s = (A**b)%37: " << s_A.uint64val() << endl;
	cout << "s values " << (s_A == s_B ? "match" : "don't match") << endl;

	cout << "Big values:" << endl;

	ByteVector bv = ByteVector("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", HEX);
	ByteVectorMath p1 = ByteVectorMath(bv, false); // not sure if this is meant to be most significant byte first or not
	ByteVectorMath g1 = ByteVectorMath(2);
	
	// random values on 0..p1-1
	ByteVectorMath a1 = ByteVectorMath();
	ByteVectorMath b1 = ByteVectorMath();
	a1.random(p1);
	b1.random(p1);
	cout << "Got here 1" << endl;
	ByteVectorMath A1 = ByteVectorMath(g1, false);
	cout << "Got here 2" << endl;
	A1.modExpSelf(a1, p1);
	cout << "Got here 3" << endl;
	ByteVectorMath B1 = ByteVectorMath(g1, false);
	B1.modExpSelf(b1, p1);
	cout << "Got here 4" << endl;
	ByteVectorMath s_A1 = ByteVectorMath(A1, false);
	ByteVectorMath s_B1 = ByteVectorMath(B1, false);
	s_A1.modExpSelf(b1, p1);
	s_B1.modExpSelf(a1, p1);

	cout << "s values " << (s_A1 == s_B1 ? "match" : "don't match") << endl;


}

int Set5() {
	cout << "### SET 5 ###" << endl;
	cout << "Set 5 Challenge 33" << endl;
	Set5Challenge33();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
}