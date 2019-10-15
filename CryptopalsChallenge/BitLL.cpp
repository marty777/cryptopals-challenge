#include "BitLL.h"
#include "ByteVector.h"
#include <iostream>


BitLL::BitLL()
{
	this->len = 0;
	this->first = NULL;
	this->last = NULL;
}


BitLL::~BitLL()
{
	if (this->first != NULL) {
		int count = 0;
		BitLLNode *node = this->last;
		BitLLNode *temp;
		while (node != NULL) {
			count++;
			temp = node->prev;
			delete node;
			node = temp;
		}
		this->len = 0;
		this->first = NULL;
		this->last = NULL;
	}
}

BitLL::BitLL(ByteVector *m) {
	size_t hi_bit = 8 * m->length() - 1;
	while (hi_bit > 0) {
		if ((*m)[hi_bit / 8] >> 7 - (hi_bit % 8)) {
			break;
		}
		hi_bit--;
	}
	BitLLNode *prev = NULL;
	for (size_t i = 0; i < hi_bit; i++) {
		BitLLNode *n = new BitLLNode();
		n->val = 0x01 & ((*m)[i / 8] >> 7 - (i % 8));
		if (i == 0) {
			this->first = n;
		}
		else {
			n->prev = prev;
			prev->next = n;
			if (i == hi_bit - 1) {
				this->last = n;
			}
		}
		prev = n;
		this->len++;
	}
}
BitLL::BitLL(size_t val) {
	size_t hi_bit = 63;
	while (hi_bit > 0) {
		if (0x1 & (val >> (hi_bit)) == 1) {
			break;
		}
		hi_bit--;
	}
	BitLLNode *prev = NULL;
	for (size_t i = 0; i <= hi_bit; i++) {
		BitLLNode *n = new BitLLNode();
		n->val = 0x1 & (val >> (i));
		if (i == 0) {
			this->first = n;
		}
		else {
			n->prev = prev;
			prev->next = n;
			if (i == hi_bit - 1) {
				this->last = n;
			}
		}
		prev = n;
		this->len++;
	}
	if (prev != NULL) {
		this->last = prev;
	}
}

// clear current list and replace with b
void BitLL::operator = (BitLL b) {
	this->clear();
	BitLLNode *n = b.first;
	while (n != NULL) {
		this->push(n->val);
		n = n->next();
	}
}

bool BitLL::operator == (BitLL b) {
	// test if all set bits are equivalent. For lists of unequal length, take missing bits to be zero
	BitLLNode *a_n = this->first;
	BitLLNode *b_n = b.first;
	while (a_n != NULL || b_n != NULL) {
		bool a_val = a_n == NULL ? 0 : a_n->val;
		bool b_val = b_n == NULL ? 0 : b_n->val;
		if (a_val != b_val) {
			return false;
		}
	}
	return true;
}

bool BitLL::operator < (BitLL b) {

}
bool BitLL::operator > (BitLL b) {

}


// returns false if memory won't allocate
bool BitLL::push(bool bit) {
	BitLLNode *n = new BitLLNode();
	if (n == NULL) {
		return false;
	}
	n->val = bit;
	n->next = NULL;
	n->prev = this->last;
	if (this->last != NULL) {
		this->last->next = n;
		this->last = n;
	}
	else {
		this->first = n;
		this->last = n;
	}
	this->len++;
	return true;
}
// remove and return final value. If length is 0, returns false;
bool BitLL::pop() {
	if (this->len == 0) {
		return false;
	}
	BitLLNode *n = this->last;
	bool ret = n->val;
	this->last  = n->prev;
	this->last->next = NULL;
	this->len--;
	delete n; // for speed, may want to let automatic collection handle it later rather than dealloc one node at a time, not sure.
	return ret;
}

// front push
bool BitLL::fpush(bool bit) {
	BitLLNode *n = new BitLLNode();
	if (n == NULL) {
		return false;
	}
	n->val = bit;
	n->prev = NULL;
	n->next = this->first;
	if (n->next != NULL) {
		this->first->prev = n;
	}
	else {
		this->last = n;
	}
	this->first = n;
	this->len++;
	return true;
}
// front pop
bool BitLL::fpop() {
	if (this->len == 0) {
		return false;
	}
	BitLLNode *n = this->first;
	bool ret = n->val;
	this->first = n->next;
	this->first->prev = NULL;
	this->len--;
	delete n; // for speed, may want to let automatic collection handle it later rather than dealloc one node at a time, not sure.
	return ret;
}

// remove up to shift elements from start of list
void BitLL::lshift(size_t shift) {
	for (size_t index = 0; index < shift; index++) {
		this->fpop();
	}
}
// add shift elements at start of list
void BitLL::rshift(size_t shift) {
	for (size_t index = 0; index < shift; index++) {
		this->fpush(0);
	}
}
// remove all elements in list
void BitLL::clear() {
	while (this->len > 0) {
		this->pop();
	}
}

void BitLL::andSelf(BitLL *bll) {
	// for lists of unequal length, treat unavailable bits as zeroes
	BitLLNode *a = this->first;
	BitLLNode *b = bll->first;
	while (a != NULL) {
		if (b == NULL) {
			a->val = 0;
		}
		else {
			a->val = a->val & b->val;
			b = b->next;
		}
		a = a->next;
	}
}
void BitLL::orSelf(BitLL *bll) {
	// for lists of unequal length, treat unavailable bits as zeroes
	BitLLNode *a = this->first;
	BitLLNode *b = bll->first;
	while (a != NULL) {
		if (b == NULL) {
			break;
		}
		else {
			a->val = a->val | b->val;
			b = b->next;
		}
		a = a->next;
		if (a == NULL && b != NULL) {
			this->push(0);
			a = this->last;
		}
	}
}
void BitLL::xorSelf(BitLL *bll) {
	// for lists of unequal length, treat unavailable bits as zeroes
	BitLLNode *a = this->first;
	BitLLNode *b = bll->first;
	while (a != NULL) {
		if (b == NULL) {
			break;
		}
		else {
			a->val = a->val ^ b->val;
			b = b->next;
		}
		a = a->next;
		if (a == NULL && b != NULL) {
			this->push(0);
			a = this->last;
		}
	}
}

char *BitLL::toStr(bll_str_format format) {
	char *str = NULL;
	const char *hex = "0123456789abcdef";
	if (this->first == NULL) {
		return "";
	}
	BitLLNode *n = this->first;
	size_t index = 0;
	switch (format) {
		case BITLL_ASCII:
			str = new char[this->len/8 + 1];
			str[0] = 0;
			while (n != NULL) {
				if (index % 8 == 0) {
					str[index / 8] = 0;
				}
				str[index / 8] |= n->val << (index % 8);
				index++;
				n = n->next;
			}
			str[this->len/8] = '\0';
			break;
		case BITLL_BINARY:
			str = new char[this->len + 1];
			while (n != NULL) {
				str[index] = n->val == 1 ? '1' : '0';
				index++;
				n = n->next;
			}
			str[this->len] = '\0';
			break;
		case BITLL_HEX:
			str = new char[this->len / 4 + 1];
			str[0] = 0;
			byte acc = 0;
			while (n != NULL) {
				if (index % 4 == 0) {
					acc = 0;
				}
				acc |= n->val << (index % 4);
				if (index % 4 == 3) {
					str[index / 4] = hex[acc];
				}
				index++;
				n = n->next;
			}
			str[this->len / 8] = '\0';
	}
	return str;
}

