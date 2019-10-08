#include "ByteVectorMath.h"



ByteVectorMath::ByteVectorMath()
{
}
ByteVectorMath::ByteVectorMath(uint32_t a) {
	// least significant bits first
	this->resize(4);
	(*this)[0] = bitwiseReverse[0xff & (a)];
	(*this)[1] = bitwiseReverse[0xff & (a >> 8)];
	(*this)[2] = bitwiseReverse[0xff & (a >> 16)];
	(*this)[3] = bitwiseReverse[0xff & (a >> 24)];
}
ByteVectorMath::ByteVectorMath(ByteVector a) {
	// least significant bits first
	this->resize(a.length());
	for (size_t i = 0; i < a.length(); i++) {
		(*this)[i] = bitwiseReverse[a[a.length() - 1 - i]];
	}
}

ByteVectorMath::~ByteVectorMath()
{
}


void ByteVectorMath::add(ByteVectorMath a, ByteVectorMath b) {

	byte carry = 0;

	/*while (b != 0) {

	}*/
}

byte ByteVectorMath::byteReverse(byte b) {
	return bitwiseReverse[b];
}