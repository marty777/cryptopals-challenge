#include "BNUtility.h"
#include <iostream>

BIGNUM *bn_from_word(unsigned long long word) {
	BIGNUM *b = BN_new();
	BN_set_word(b, word);
	return b;
}

BIGNUM *bn_from_bytevector(ByteVector *src) {
	BIGNUM *b = BN_new();
	BN_bin2bn(src->dataPtr(), src->length(), b);
	return b;
}

void bn_to_bytevector(BIGNUM *src, ByteVector *dest) {
	size_t len = BN_num_bytes(src);
	unsigned char* bin = (unsigned char*)malloc(len * sizeof(unsigned char));
	BN_bn2bin(src, bin);
	dest->resize(len);
	for (size_t i = 0; i < len; i++) {
		(*dest)[i] = bin[i];
	}
	free(bin);
}

void bn_print(BIGNUM * b, bv_str_format format) {
	ByteVector bv = ByteVector();
	bn_to_bytevector(b, &bv);
	char* buf = bv.toStr(format);
	std::cout << buf << std::endl;
}