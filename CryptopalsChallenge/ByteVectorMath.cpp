#include "ByteVectorMath.h"
#include <iostream>


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
ByteVectorMath::ByteVectorMath(ByteVector a, bool flip) {
	// least significant bits first
	this->resize(a.length());
	for (size_t i = 0; i < a.length(); i++) {
		if (flip) {
			(*this)[i] = bitwiseReverse[a[a.length() - 1 - i]];
		}
		else {
			(*this)[i] = a[i];
		}
	}
}

ByteVectorMath::~ByteVectorMath()
{
}

// slow, possibly leaky
void ByteVectorMath::addSelf(ByteVectorMath b) {
	ByteVector carry = (*this) & b;
	ByteVector result = (*this) ^ b;
	carry.truncateRight();
	size_t carry_rshift = 0;
	while (carry.length() > 0) {	
		ByteVector shiftedCarry = carry >> 1;
		carry = result & shiftedCarry;
		result.xorSelf(&shiftedCarry);
		carry.truncateRight();
	}
	this->resize(result.length());
	result.copyBytesByIndex(this, 0, result.length(), 0);
}

// Not sure this handles a negative result well
void ByteVectorMath::subtractSelf(ByteVectorMath b) {
	ByteVector carry = ~(*this) & b;
	ByteVector result = (*this) ^ b;
	carry.truncateRight();
	size_t carry_rshift = 0;
	while (carry.length() > 0) {
		ByteVector shiftedCarry = carry >> 1;
		carry = result & shiftedCarry;
		result.xorSelf(&shiftedCarry);
		carry.truncateRight();
	}
	this->resize(result.length());
	result.copyBytesByIndex(this, 0, result.length(), 0);
}

void ByteVectorMath::multiplySelf(ByteVectorMath b) {
	// Russian peasant
	ByteVectorMath a = ByteVectorMath(this, false);
	ByteVectorMath result = ByteVectorMath(0);
	while (b.length() > 0) {
		std::cout << "Start round:" << std::endl;
		std::cout << "A: " << a.toStr(BINARY) << std::endl;
		std::cout << "B: " << b.toStr(BINARY) << std::endl;
		if (b[0] >> 7 != 0) {
			std::cout << "Add A" << std::endl;
			result.addSelf(a);
			std::cout << "Result: " << result.toStr(BINARY) << std::endl;
		}
		a.rightShiftSelf(1);
		b.leftShiftSelf(1);
		b.truncateRight();
	}
	this->resize(result.length());
	result.copyBytesByIndex(this, 0, result.length(), 0);
}

byte ByteVectorMath::byteReverse(byte b) {
	return bitwiseReverse[b];
}

size_t ByteVectorMath::uint64val() {
	// only work with first 64 bits
	size_t result = bitwiseReverse[(*this)[7]] << 56 |
					bitwiseReverse[(*this)[6]] << 48 |
					bitwiseReverse[(*this)[5]] << 40 |
					bitwiseReverse[(*this)[4]] << 32 |
					bitwiseReverse[(*this)[3]] << 24 |
					bitwiseReverse[(*this)[2]] << 16 |
					bitwiseReverse[(*this)[1]] << 8 |
					bitwiseReverse[(*this)[0]];
	return result;
	
}