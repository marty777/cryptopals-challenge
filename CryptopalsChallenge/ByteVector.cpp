#include "ByteVector.h"
#include <iostream>
#include <assert.h>

char indexToCharBase64(unsigned int index) {
	if (index <= 25) {
		return (char)65 + index;
	}
	else if (index <= 51) {
		return (char)97 + index - 26;
	}
	else if (index <= 61) {
		return (char)48 + index - 52;
	}
	else if (index == 62) {
		return '+';
	}
	else if (index == 63) {
		return '/';
	}
	return ' ';
}

 int charToIndexBase64(char c) {
	if (c >= 65 && c <= 90) {
		return c - 65;
	}
	else if (c >= 97 && c <= 122) {
		return c - 71;
	}
	else if (c >= 48 && c <= 57) {
		return c + 4;
	}
	else if (c == 43) {
		return 62;
	}
	else if (c == 47) {
		return 63;
	}
	else if (c == 61) { // kludge for the = padding.
		return 100;
	}
	return -1;
}

ByteVector::ByteVector(char *input, bv_str_format format) {
	switch (format) {
	case ASCII: {
		_v.resize(strlen(input));
		for (size_t i = 0; i < strlen(input); i++) {
			_v[i] = input[i];
		}
		break;
	}
	case BINARY: {
		if ((strlen(input) % 8) != 0) {
			throw - 1;
		}
		_v.resize(strlen(input) / 8);
		for (size_t i = 0; i < _v.size(); i++) {
			byte b = 0;
			for (size_t j = 0; j < 8; j++) {
				size_t index = 8 * i + j;
				if (input[index] == '1') {
					byte c = 1 << (8 - j - 1);
					b |= c;
				}
			}
			_v[i] = b;
		}
		break;
	}
	case HEX: {
		if ((strlen(input) % 2) != 0) {
			throw - 1;
		}
		_v.resize(strlen(input) / 2);
		for (size_t i = 0; i < _v.size(); i++) {
			byte b = 0;
			char c1 = (byte)input[i * 2];
			char c2 = (byte)input[(i * 2) + 1];
			if (c1 >= 0x30 && c1 <= 0x39) {
				b = ((c1 - 0x30) << 4);
			}
			else if (c1 >= 0x61 && c1 <= 0x66) {
				b = (byte)((int)((10 + (c1 - 0x61)) << 4));
			}

			if (c2 >= 0x30 && c2 <= 0x39) {
				b |= ((c2 - 0x30));
			}
			else if (c2 >= 0x61 && c2 <= 0x66) {
				b |= (10 + (c2 - 0x61));
			}

			_v[i] = b;
		}

		break;
	}
	case BASE64: {
		// It's useful to have this skip all non-base64 characters in the input string.
		// 6 bits per char
		
		size_t inputlen = strlen(input);
		int inputCount = 0;
		// determine size to allocate - this count skips padding characters
		for (size_t i = 0; i < inputlen; i++) {
			if (charToIndexBase64(input[i]) >= 0 && charToIndexBase64(input[i]) != 100) {
				inputCount++;
			}
		}
		
		int byteCount = 3*(inputCount / 4);
		if(inputCount % 4 == 3) {
			byteCount += 2;
		}
		else if (inputCount % 4 == 2) {
			byteCount += 1;
		}
		_v.resize(byteCount);
		size_t i = 0;
		size_t k = 0;
		byte accumulator = 0;
		bool done = false;
		int j = 0;
		while (i < inputlen && !done) {
			
			int index = charToIndexBase64(input[i]);
			//std::cout << index;
			if (index > -1) {
				if (j == 0) {
					accumulator = 0xff & (index << 2);
				}
				else if (j == 1) {
					accumulator = accumulator | (index >> 4);
					_v[k] = accumulator;
					k++;
					accumulator = 0xff & (index << 4);
				}
				else if (j == 2) {
					if (index != 100) {
						accumulator = accumulator | (index >> 2);
						_v[k] = accumulator;
						k++;
						accumulator = 0xff & (index << 6);
					}
					else {
						done = true;
					}
				}
				else if (j == 3) {
					if (index != 100) {
						accumulator = accumulator | index;
						_v[k] = accumulator;
						k++;
						accumulator = 0;
						j = -1;
					}
					else {
						done = true;
					}
				}
				j++;
			}
			i++;
		}
		break;
	}
	default:
		break;
	}
}
ByteVector::ByteVector(ByteVector *bv) {
	_v.resize(bv->length());
	for (int i = 0; i < bv->length(); i++) {
		_v[0] = bv->atIndex(i);
	}
}
ByteVector::ByteVector(byte *source, size_t len) {
	_v.resize(len);
	for (size_t i = 0; i < len; i++) {
		_v[i] = source[i];
	}
}
ByteVector::ByteVector(size_t len) {
	_v.resize(len);
}
ByteVector::ByteVector() {
	_v.resize(0);
}

ByteVector::~ByteVector() {
	_v.~vector();
}


size_t ByteVector::length() {
	return _v.size();
}
byte ByteVector::atIndex(size_t index) {
	assert(index < _v.size());
	return _v[index];
}
byte ByteVector::setAtIndex(byte value, size_t index) {
	if (index >= _v.size()) {
		throw -1;
	}
	_v[index] = value;
}
bool ByteVector::equal(ByteVector *bv) {
	if (bv->length() != _v.size()) {
		return false;
	}
	bool equal = true;
	for (size_t i = 0; i < _v.size(); i++) {
		if (bv->atIndex(i) != _v[i]) {
			equal = false;
			break;
		}
	}
	return equal;
}

bool ByteVector::equalAtIndex(ByteVector *bv, size_t start_index, size_t length, size_t input_start_index) {
	assert(start_index + length <= _v.size() && input_start_index + length <= bv->length());
	
	bool equal = true;
	for (size_t i = 0; i < length; i++) {
		if (bv->atIndex(input_start_index + i) != _v[start_index + i]) {
			equal = false;
			break;
		}
	}
	return equal;
}

// Arguments:
//	*bv		- comparison vector pointer
//  subset	- optional, use start and end indexes for comparison, not both full vectors
//	start_a - start comparison index for this vector
//  end_a	- end comparison index for this vector
//	start_b	- start comparison index for the provided vector bv
//  end_b	- end comparison index for provided vector
size_t ByteVector::hammingDistance(ByteVector *bv, bool subset, size_t start_a, size_t end_a, size_t start_b, size_t end_b) {
	if (subset) {
		// 0 length comparisons are allowed (start_a = start_b, for example)
		if (start_a >= bv->length() || end_a > bv->length() || start_a > end_a ||
			start_b >= bv->length() || end_b > bv->length() || start_b > end_b) {
			return 0;
		}
	}
	else {
		start_a = 0;
		end_a = _v.size() - 1;
		start_b = 0;
		end_b = bv->length() - 1;
	}
	int dist = 0;
	size_t i = start_a;
	size_t j = start_b;
	while (i <= end_a && j <= end_b) {
		byte xor = _v[i] ^ bv->atIndex(j);
		for (int k = 0; k < 8; k++) {
			dist += (0x01) & (xor >> k);
		}
		i++;
		j++;
	}

	// for vectors of unequal length, count missing bytes as 0s.
	// edit: that's insane. every additional bit is a difference, and comparison strings of uneven length don't even make sense for a hamming distance.
	while (i <= end_a) {
		/*std::cout << "Got 1 " << i << " " << end_a << std::endl;
		for (int k = 0; k < 8; k++) {
			dist += (0x01) & (_v[i] >> k);
		}*/
		dist += 8;
		i++;
	}
	while (j <= end_b) {

		/*std::cout << "Got 2" << j << " " << end_b << std::endl;
		for (int k = 0; k < 8; k++) {
			dist += (0x01) & (bv->atIndex(j) >> k);
		}*/
		dist += 8;
		j++;
	}
	return dist;
}

// XOR input vector of arbitrary length with this one and return result
ByteVector ByteVector:: xor (ByteVector *bv) {
	ByteVector bv2 = new ByteVector(_v.size());
	size_t j = 0;
	for (size_t i = 0; i < _v.size(); i++) {
		if (j >= bv->length()) {
			j = 0;
		}
		bv2.setAtIndex(bv->atIndex(j) ^ _v[i], i);
		j++;
	}
	return bv2;
}


// XOR input vector with this one starting and ending at specified indexes
void ByteVector:: xorByIndex(ByteVector *bv, size_t start_index, size_t length, size_t input_start_index) {
	assert(bv->length() > input_start_index && bv->length() >= input_start_index + length && _v.size() > start_index && _v.size() >= start_index + length);

	for (size_t i = 0; i < length; i++) {
		_v[start_index + i] = _v[start_index + i] ^ bv->atIndex(input_start_index + i);
	}
}
char *ByteVector::toStr(bv_str_format format) {
	char *str = NULL;
	const char *hex = "0123456789abcdef";
	const char *base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	switch (format) {

	case ASCII:
		str = new char[_v.size() + 1];
		for (int i = 0; i < _v.size(); i++) {
			str[i] = _v[i];
		}
		str[_v.size()] = '\0';
		break;
	case BINARY:
		str = new char[_v.size() * 8 + 1];

		for (int i = 0; i < _v.size(); i++) {
			for (int j = 0; j < 8; j++) {
				str[i * 8 + j] = ((_v[i] >> (7 - j)) & 0x1) == 1 ? '1' : '0';
			}
		}
		str[_v.size() * 8] = '\0';
		break;
	case HEX:
		str = new char[(_v.size() * 2) + 1];

		for (int i = 0; i < _v.size(); i++) {
			str[i * 2] = hex[(_v[i] >> 4) & 0xf];
			str[(i * 2) + 1] = hex[(_v[i]) & 0xf];
		}

		str[(_v.size() * 2)] = '\0';
		break;
	case BASE64:
		size_t size = ((_v.size() * 4) / 3);
		if (_v.size() % 3 == 1) {
			size += 3;
		}
		else if (_v.size() % 3 == 2) {
			size += 2;
		}
		str = new char[size + 1];
		size_t j = 0;
		size_t i = 0;
		byte accumulator = 0;
		while (i < _v.size()) {
			if (i % 3 == 0) {
				accumulator = (_v[i] >> 2);
				str[j] = base64[accumulator];
				j++;
				accumulator = 0x30 & (_v[i] << 4);
			}
			else if (i % 3 == 1) {
				accumulator = accumulator | (_v[i] >> 4);
				str[j] = base64[accumulator];
				j++;
				accumulator = (_v[i] & 0xf) << 2;
			}
			else if (i % 3 == 2) {
				accumulator = accumulator | (_v[i] >> 6);
				str[j] = base64[accumulator];
				j++;
				accumulator = 0x3f & _v[i];
				str[j] = base64[accumulator];
				j++;
				accumulator = 0;
			}
			i++;
		}
		if (_v.size() % 3 == 1) {
			str[j] = base64[accumulator];
			j++;
			str[j] = '=';
			j++;
			str[j] = '=';
		}
		else if (_v.size() % 3 == 2) {
			str[j] = base64[accumulator];
			j++;
			str[j] = '=';
		}

		str[size] = '\0';
		break;
	}
	return str;
}


void ByteVector::printHexStrByBlocks(size_t blocksize) {
	const char *hex = "0123456789abcdef";
	for (size_t i = 0; i <=  _v.size()/blocksize; i++) {
		std::cout << i << ": ";
		for (size_t j = i*blocksize; j < (i + 1)*blocksize && j < _v.size(); j++) {
			byte val = _v[j];
			byte a = (val & 0xf0) >> 4;
			byte b = val & 0x0f;
			std::cout << hex[a] << hex[b];
		}
		std::cout << std::endl;
		if (i*blocksize + blocksize >= _v.size()) {
			break;
		}
	}
}

void ByteVector::printASCIIStrByBlocks(size_t blocksize) {
	for (size_t i = 0; i <= _v.size() / blocksize; i++) {
		std::cout << i << ": ";
		for (size_t j = i*blocksize; j < (i + 1)*blocksize && j < _v.size(); j++) {
			byte val = _v[j];
			
			std::cout << val;
		}
		std::cout << std::endl;
		if (i*blocksize + blocksize >= _v.size()) {
			break;
		}
	}
}

// copy to a pre-allocated byte array of appropriate size
void ByteVector::copyBytes(byte *dest) {
	for (size_t i = 0; i < _v.size(); i++) {
		dest[i] = _v[i];
	}
}

void ByteVector::copyBytes(ByteVector *dest) {
	for (size_t i = 0; i < _v.size(); i++) {
		dest->setAtIndex(_v[i],i);
	}
}

// copy a section to an arbitrary index of another vector.
void ByteVector::copyBytesByIndex(ByteVector * dest, size_t start_index, size_t length, size_t dest_index) {
	assert(length <= dest->length() - dest_index);
	for (size_t i = start_index; i < start_index + length; i++) {
		dest->setAtIndex(_v[i], dest_index + i - start_index);
	}
}

void ByteVector::padToLength(size_t len, byte padding) {	
	if (len < _v.size()) {
		return;
	}
	size_t startlen = _v.size();
	_v.resize(len);
	for (size_t i = startlen; i < len; i++) {
		_v[i] = padding;
	}
}

// set all bytes to pseudorandom values using rand()
void ByteVector::random() {
	for (size_t i = 0; i < _v.size(); i++) {
		_v[i] = (byte)(rand() % 0x100);
	}
}

void ByteVector::reverse() {
	ByteVector temp = ByteVector(_v.size());
	for (size_t i = temp.length() - 1; i >= 0; i--) {
		temp.setAtIndex(_v[temp.length() - 1 - i], i);
	}
	for (size_t i = 0; i < temp.length(); i++) {
		_v[i] = temp.atIndex(i);
	}
}

// set all bytes in vector to provided
void ByteVector::allBytes(byte value) {
	for (size_t i = 0; i < _v.size(); i++) {
		_v[i] = value;
	}
}

void ByteVector::append(byte b) {
	_v.push_back(b);
}

void ByteVector::resize(size_t len) {
	_v.resize(len);
}

// exposing this kind of negates having the vector as a private member, but I'm building this as I go.
byte *ByteVector::dataPtr() {
	return _v.data();
}

