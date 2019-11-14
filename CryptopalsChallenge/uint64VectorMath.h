#pragma once
#include <vector>
#include "ByteVector.h"

// hi bit first endianess, hi word last array ordering

class uint64VectorMath
{
private:
	std::vector<uint64_t> _v;
public:
	uint64VectorMath();
	~uint64VectorMath();
	uint64VectorMath(uint64VectorMath *a);
	uint64VectorMath(uint64_t a);
	uint64VectorMath(ByteVector *a);

	uint64_t operator[] (size_t n) const;
	uint64_t& operator [] (size_t n);

	uint64VectorMath operator >> (size_t n);
	uint64VectorMath operator << (size_t n);
	uint64VectorMath operator & (uint64VectorMath b);
	uint64VectorMath operator | (uint64VectorMath b);
	uint64VectorMath operator ^ (uint64VectorMath b);
	uint64VectorMath operator ~ ();

	bool operator == (uint64VectorMath b);
	bool operator != (uint64VectorMath b);
	bool operator > (uint64VectorMath b);
	bool operator < (uint64VectorMath b);

	void resize(size_t len);
	void reserve(size_t len);
	size_t length();
	size_t hibit();

	void truncLeft();

	void lshiftSelf(size_t shift);
	void rshiftSelf(size_t shift);

	bool getBit(size_t index);
	void setBit(bool val, size_t index);

	void notSelf();
	void andSelf(uint64VectorMath *b);
	void orSelf(uint64VectorMath *b);
	void xorSelf(uint64VectorMath *b);

	void copyToSelf(uint64VectorMath *b);
	void addSelf(uint64VectorMath *b);
	void subtractSelf(uint64VectorMath *b);
	void divideSelf(uint64VectorMath *b, uint64VectorMath *remainder);
	void modSelf(uint64VectorMath *mod);
	void modMultSelf(uint64VectorMath *b, uint64VectorMath *mod);
	void modExpSelf(uint64VectorMath *exp, uint64VectorMath *mod);

	uint64_t uint64val(size_t index);
	void printHex();
	void copyToByteVector(ByteVector *bv);
};

