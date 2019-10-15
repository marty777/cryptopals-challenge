#pragma once
#include "ByteVector.h"

enum bll_str_format { BITLL_ASCII, BITLL_BINARY, BITLL_HEX };

class BitLL{

public:

	struct BitLLNode {
		friend BitLL;
		bool val;
		BitLLNode *next;
		BitLLNode *prev;
	};

	BitLL();
	~BitLL();
	BitLL(ByteVector *m);
	BitLL(size_t val);

	void operator = (BitLL b);
	bool operator == (BitLL b);
	bool operator < (BitLL b);
	bool operator > (BitLL b);

	bool push(bool bit);
	bool pop();
	bool fpush(bool bit);
	bool fpop();
	void clear();
	
	void lshift(size_t shift);
	void rshift(size_t shift);
	void andSelf(BitLL *bll);
	void orSelf(BitLL *bll);
	void xorSelf(BitLL *bll);
	char *toStr(bll_str_format format);

private:
	size_t len;
	BitLLNode *first;
	BitLLNode *last;
};

