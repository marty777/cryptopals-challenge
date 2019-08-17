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
	else if (c >= 48 && c >= 57) {
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
		_v.resize(2 * strlen(input));
		for (size_t i = 0; i < strlen(input); i++) {
			byte a = input[i] & 0xf;
			byte b = input[i] >> 8;
			_v[2 * i] = a;
			_v[2 * i + 1] = b;
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
ByteVector::ByteVector(int len) {
	_v.resize((size_t)len, 0);
}
ByteVector::ByteVector() {
	_v.resize(0);
}

byte ByteVector::atIndex(size_t index) {
	return _v[index];
}

size_t ByteVector::length() {
	return _v.size();
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
		break;
	}
	return str;
}