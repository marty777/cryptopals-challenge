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
	BitLL(BitLL *b);
	BitLL(ByteVector *m);
	BitLL(size_t val);

	size_t size();

	void operator = (BitLL *b);
	bool operator == (BitLL *b);
	bool operator < (BitLL *b);
	bool operator > (BitLL *b);
	bool operator <= (BitLL *b);
	bool operator >= (BitLL *b);

	bool push(bool bit);
	bool pop();
	bool fpush(bool bit);
	bool fpop();
	void clear();

	size_t hi_bit();
	void truncRight();

	void notSelf();
	void lshift(size_t shift);
	void rshift(size_t shift);
	void andSelf(BitLL *bll);
	void orSelf(BitLL *bll);
	void xorSelf(BitLL *bll);
	
	void modSelf(BitLL *bll);
	void modMultSelf(BitLL *bll, BitLL *mod);
	void modExpSelf(BitLL *exp, BitLL *mod);
	void addSelf(BitLL *bll);
	void subtractSelf(BitLL *bll);
	void multSelf(BitLL *bll);

	void random(size_t length);
	void randomMod(BitLL *mod);

	char *toStr(bll_str_format format);
	size_t uint64();

private:
	size_t len;
	BitLLNode *first;
	BitLLNode *last;
};

