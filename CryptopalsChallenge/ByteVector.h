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
	ByteVector(byte *source, size_t len);
	ByteVector(size_t len);
	ByteVector();
	~ByteVector();

	byte operator[] (size_t n) const;
	byte& operator [] (size_t n);

	ByteVector operator >> (size_t n);
	ByteVector operator << (size_t n);
	ByteVector operator & (ByteVector b);
	ByteVector operator | (ByteVector b);
	ByteVector operator ^ (ByteVector b);
	ByteVector operator ~ ();
	
	size_t length();
	byte atIndex(size_t index);
	byte setAtIndex(byte value, size_t index);
	bool equal(ByteVector *bv);
	bool equalAtIndex(ByteVector *bv, size_t start_index, size_t length, size_t input_start_index);
	size_t hammingDistance(ByteVector *bv, bool subset = false, size_t start_a = 0, size_t end_a = 0, size_t start_b = 0, size_t end_b = 0);

	ByteVector xorRepeat(ByteVector *bv);
	ByteVector xor(ByteVector *bv);
	void xorSelf (ByteVector *bv);
	void xorWithStream(ByteVector *bv);
	void xorByIndex(ByteVector *bv, size_t start_index, size_t length, size_t input_start_index);
	ByteVector and(ByteVector *bv);
	void andSelf(ByteVector *bv);
	void truncateLeft();
	void truncateRight();
	void leftShiftSelf(size_t shift);
	void rightShiftSelf(size_t shift);

	char *toStr(bv_str_format format);
	void printHexStrByBlocks(size_t blocksize);
	void printHexStrByBlocksPartial(size_t blocksize, size_t start_index, size_t end_index);
	void printASCIIStrByBlocks(size_t blocksize);

	void copyBytes(byte *dest);
	void copyBytes(ByteVector *dest);
	void copyBytesByIndex(ByteVector * dest, size_t start_index, size_t length, size_t dest_index);
	void padToLength(size_t len, byte padding);
	void padToLengthPKCS7(size_t len);
	void random();
	void reverse();
	void allBytes(byte value);

	void append(byte b);
	void append(ByteVector *bv);

	void reserve(size_t len);
	void resize(size_t len);
	byte *dataPtr();
};

