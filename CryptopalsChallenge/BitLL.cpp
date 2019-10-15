#include "BitLL.h"
#include "ByteVector.h"


BitLL::BitLL()
{
	this->len = 0;
	this->first = NULL;
	this->last = NULL;
}


BitLL::~BitLL()
{
	if (this->first != NULL) {

	}

	BitLLNode *next = this->first;
	BitLLNode *temp;
	while (next->next != NULL) {
		temp = next->next;
		delete next;
		next = temp;
	}
	delete next;
	this->len = 0;
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
		BitLLNode n;
		n.val = 0x01 & ((*m)[i / 8] >> 7 - (i % 8));
		if (i == 0) {
			this->first = &n;
		}
		else {
			n.prev = prev;
			prev->next = &n;
			if (i == hi_bit - 1) {
				this->last = &n;
			}
		}
		prev = &n;
		this->len++;
	}
}
BitLL::BitLL(size_t val) {
	size_t hi_bit = 63;
	while (hi_bit > 0) {
		if (0x1 & (val >> (63 - hi_bit)) == 1) {
			break;
		}
		hi_bit--;
	}
	BitLLNode *prev = NULL;
	for (size_t i = 0; i < hi_bit; i++) {
		BitLLNode n;
		n.val = 0x1 & (val >> (63 - hi_bit));
		if (i == 0) {
			this->first = &n;
		}
		else {
			n.prev = prev;
			prev->next = &n;
			if (i == hi_bit - 1) {
				this->last = &n;
			}
		}
		prev = &n;
		this->len++;
	}
}


