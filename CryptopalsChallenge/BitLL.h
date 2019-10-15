#pragma once
#include "ByteVector.h"

struct BitLLNode {
	bool val;
	BitLLNode *next;
	BitLLNode *prev;
};

class BitLL
{
	size_t len;
	BitLLNode *first;
	BitLLNode *last;

public:
	BitLL();
	~BitLL();
	BitLL(ByteVector *m);
	BitLL(size_t val);
};

