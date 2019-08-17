#include "ByteVector.h"
#include <iostream>

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

unsigned int charToIndexBase64(char c) {
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

	return 0;
}

ByteVector::ByteVector(char *input, bv_str_format format) {
	switch (format) {
	case ASCII:
		_v.resize(strlen(input));
		for (size_t i = 0; i < strlen(input); i++) {
			_v[i] = input[i];
		}
		break;
	case BINARY:
		if ((strlen(input) % 8) != 0) {
			throw -1;
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
	case HEX:
		if ((strlen(input) % 2) != 0) {
			throw - 1;
		}
		_v.resize(strlen(input)/2);
		for (size_t i = 0; i < _v.size(); i++) {
			byte b = 0;
			char c1 = (byte)input[i*2];
			char c2 = (byte)input[(i*2) + 1];
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
	case BASE64:
		// 6 bits per char
		if ((strlen(input) % 4) != 0) {
			throw - 1;
		}
		_v.resize(3 * (strlen(input)/4));
		for (size_t i = 0; i < _v.size(); i+=3) {
			size_t index = 4 * (i / 3);
			
			int d1 = charToIndexBase64(input[index]);
			int d2 = charToIndexBase64(input[index + 1]);
			int d3 = charToIndexBase64(input[index + 2]);
			int d4 = charToIndexBase64(input[index + 3]);
			_v[i]= (d1 << 2) | ((d2 >> 4) & 0x3);
			_v[i + 1] = ((d2 << 4) & 0xf0) | (d3 >> 2);
			_v[i + 2] = ((d3 << 6) & 0xc0) | d4;
		}
		break;
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
ByteVector::ByteVector(size_t len) {
	_v.resize(len, 0);
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
		//std::cout << bv->length() << " " << _v.size() << "\n";
		return false;
	}
	bool equal = true;
	for (int i = 0; i < _v.size(); i++) {
		if (bv->atIndex(i) != _v[i]) {
			std::cout << i << " " << std::hex << (int)bv->atIndex(i) << " " << (int)_v[i] << "\n";
			equal = false;
			
		}
	}
	return equal;
}

int ByteVector::hammingDistance(ByteVector *bv) {
	int dist = 0;
	int i = 0;
	while (i < _v.size() && i < bv->length()) {
		byte xor = _v[i] ^ bv->atIndex(i);
		for (int j = 0; j < 8; j++) {
			dist += (0x01 & (xor >> j));
		}
		i++;
	}

	// for vectors of unequal length, count missing bytes as 0s.
	if (i < _v.size()) {
		while (i < _v.size()) {
			for (int j = 0; j < 8; j++) {
				dist += (0x01 & (_v[i] >> j));
			}
			
			i++;
		}
	}
	else if (i < bv->length()) {
		while (i < bv->length()) {
			for (int j = 0; j < 8; j++) {
				dist += (0x01 & (bv->atIndex(i) >> j));
			}
			i++;
		}
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
		//std::cout << std::hex << (int)bv->atIndex(j) << " " << (int)_v[i] << " " << (int)(bv->atIndex(j) ^ _v[i]) << std::endl;
		j++;
	}
	return bv2;
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
		// TBD
		// need to round up and pad string
		size_t size = ((_v.size() * 4) / 3);
		if ((size * 3) < (_v.size() * 4)) {
			size += 4;
		}
		str = new char[size + 1];
		int j = 0;
		for (int i = 0; i < _v.size(); i += 3) {
			byte a = _v[i];
			byte b = _v[i + 1];
			byte c = _v[i + 2];
			int d1 = a >> 2;
			int d2 = ((a & 0x3) << 4) | ((b & 0xf0) >> 4);
			int d3 = ((b & 0xf) << 2) | ((c & 0xc0) >> 6);
			int d4 = ((c & 0x3f));
			str[j] = base64[d1];
			str[j+1] = base64[d2];
			str[j+2] = base64[d3];
			str[j+3] = base64[d4];
			j += 4;
		}
		while (j < size) {
			str[j] = '=';
			j++;
		}
		str[size] = '\0';
		break;
	}
	return str;
}