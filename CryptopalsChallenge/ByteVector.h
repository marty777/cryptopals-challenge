#pragma once
#include <vector>

typedef unsigned char byte;
enum bv_str_format {ASCII, BINARY, HEX, BASE64};

// handles storage, input, output and basic operations on arrays of raw bytes
class ByteVector
{
private:
	std::vector<byte> _v;

public:
	ByteVector(char *input, bv_str_format format);
	ByteVector(ByteVector *bv);
	ByteVector(size_t len);
	ByteVector();
	~ByteVector();

	size_t length();
	byte atIndex(size_t index);
	byte setAtIndex(byte value, size_t index);
	bool equal(ByteVector *bv);
	int hammingDistance(ByteVector *bv);

	ByteVector xor(ByteVector *bv);

	char *toStr(bv_str_format format);
};

