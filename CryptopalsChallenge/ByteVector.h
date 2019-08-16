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
	ByteVector(int len);
	ByteVector();

	size_t length();
	byte atIndex(size_t index);

	char *toStr(bv_str_format format);
};

