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
BitLL::BitLL(BitLL *b) {
	this->len = 0;
	BitLLNode *n = b->first;
	while (n != NULL) {
		this->push(n->val);
		n = n->next;
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

size_t BitLL::size() {
	return this->len;
}

// clear current list and replace with b
void BitLL::operator = (BitLL *b) {
	this->clear();
	BitLLNode *n = b->first;
	while (n != NULL) {
		this->push(n->val);
		n = n->next;
	}
}

bool BitLL::operator == (BitLL *b) {
	// test if all set bits are equivalent. For lists of unequal length, take missing bits to be zero
	BitLLNode *a_n = this->first;
	BitLLNode *b_n = b->first;
	bool a_val;
	bool b_val;
	while (a_n != NULL || b_n != NULL) {
		
		if (a_n != NULL) {
			a_val = a_n->val;
			a_n = a_n->next;
		}
		else {
			a_val = 0;
		}
		
		if (b_n != NULL) {
			b_val = b_n->val;
			b_n = b_n->next;
		}
		else {
			b_val = 0;
		}
		
		if (a_val != b_val) {
			return false;
		}
		
	}
	return true;
}

bool BitLL::operator < (BitLL *b) {
	if (b->len == 0 && this->len == 0) {
		return false; // equal
	}
	// locate hi bit for both lists
	BitLLNode *a_n = this->last;
	size_t a_i = this->len;
	BitLLNode *b_n = b->last;
	size_t b_i = b->len;
	
	while (a_i > 0) {
		if (a_n->val == 1) {
			break;
		}
		a_n = a_n->prev;
		a_i--;
	}
	while (b_i > 0) {
		if (b_n->val == 1) {
			break;
		}
		b_n = b_n->prev;
		b_i--;
	}

	if (a_i > b_i) {
		a_n = NULL;
		b_n = NULL;
		return false;
	}
	else if (a_i < b_i) {
		a_n = NULL;
		b_n = NULL;
		return true;
	}
	else {
		while (a_i > 0) {
			if (a_n->val == false && b_n->val == true) {
				//a_n = NULL;
				//b_n = NULL;
				return true;
			}
			else if (a_n->val == true && b_n->val == false) {
				//a_n = NULL;
				//b_n = NULL;
				return false;
			}
			a_n = a_n->prev;
			b_n = b_n->prev;
			a_i--;
		}
		
	}
	//a_n = NULL;
	//b_n = NULL;
	return false; // equal
}
bool BitLL::operator > (BitLL *b) {
	if (b->len == 0 && this->len == 0) {
		return false; // equal
	}
	// locate hi bit for both lists
	BitLLNode *a_n = this->last;
	size_t a_i = this->len;
	BitLLNode *b_n = b->last;
	size_t b_i = b->len;
	while (a_i > 0) {
		if (a_n->val = 1) {
			break;
		}
		a_n = a_n->prev;
		a_i--;
	}
	while (b_i > 0) {
		if (b_n->val = 1) {
			break;
		}
		b_n = b_n->prev;
		b_i--;
	}
	if (a_i > b_i) {
		return true;
	}
	else if (a_i < b_i) {
		return false;
	}
	else {
		while (a_i > 0) {
			if (a_n->val == false && b_n->val == true) {
				//a_n = NULL;
				//b_n = NULL;
				return false;
			}
			else if (a_n->val == true && b_n->val == false) {
				//a_n = NULL;
				//b_n = NULL;
				return true;
			}
			a_n = a_n->prev;
			b_n = b_n->prev;
			a_i--;
		}
	}
	// final node
	return false; // equal
}
bool BitLL::operator <= (BitLL *b) {
	if (b->len == 0 && this->len == 0) {
		return true; // equal
	}
	// locate hi bit for both lists
	BitLLNode *a_n = this->last;
	size_t a_i = this->len;
	BitLLNode *b_n = b->last;
	size_t b_i = b->len;
	while (a_i > 0) {
		if (a_n->val = 1) {
			break;
		}
		a_n = a_n->prev;
		a_i--;
	}
	while (b_i > 0) {
		if (b_n->val = 1) {
			break;
		}
		b_n = b_n->prev;
		b_i--;
	}
	if (a_i > b_i) {
		return true;
	}
	else if (a_i < b_i) {
		return false;
	}
	else {
		while (a_i > 0) {
			if (a_n->val == false && b_n->val == true) {
				return true;
			}
			else if (a_n->val == true && b_n->val == false) {
				return false;
			}
			a_n = a_n->prev;
			b_n = b_n->prev;
			a_i--;
		}
	}
	// final node
	return true; // equal
}
bool BitLL::operator >= (BitLL *b) {
	if (b->len == 0 && this->len == 0) {
		return true; // equal
	}
	// locate hi bit for both lists
	BitLLNode *a_n = this->last;
	size_t a_i = this->len;
	BitLLNode *b_n = b->last;
	size_t b_i = b->len;
	while (a_i > 0) {
		if (a_n->val = 1) {
			break;
		}
		a_n = a_n->prev;
		a_i--;
	}
	while (b_i > 0) {
		if (b_n->val = 1) {
			break;
		}
		b_n = b_n->prev;
		b_i--;
	}
	if (a_i > b_i) {
		return true;
	}
	else if (a_i < b_i) {
		return false;
	}
	else {
		while (a_i > 0) {
			if (a_n->val == false && b_n->val == true) {
				return false;
			}
			else if (a_n->val == true && b_n->val == false) {
				return true;
			}
			a_n = a_n->prev;
			b_n = b_n->prev;
			a_i--;
		}
	}
	// final node
	return true; // equal
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
	else if (this->len == 1) {
		bool ret = this->first->val;
		delete this->first;
		this->first = NULL;
		this->last = NULL;
		this->len = 0;
		return ret;
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
// remove all elements in list
void BitLL::clear() {
	while (this->len > 0) {
		this->pop();
	}
}

// note that if zero, function will return a zero index for a hi bit.
size_t BitLL::hi_bit() {
	if (this->len == 0) {
		return 0;
	}
	size_t index = this->len - 1;
	BitLLNode *n = this->last;
	while (n != NULL) {
		if (n->val) {
			break;
		}
		n = n->prev;
		index--;
	}
	return index;
}

void BitLL::truncRight() {
	if (this->len == 0) {
		return;
	}
	size_t index = this->len - 1;
	BitLLNode *n = this->last;
	while (this->len > 0) {
		bool val = this->pop();
		if (val) {
			this->push(true);
			break;
		}
	}
}

void BitLL::notSelf() {
	BitLLNode *n = this->first;
	while (n != NULL) {
		n->val = !(n->val);
		n = n->next;
	}
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

void BitLL::modSelf(BitLL *bll) {
	if (*this < bll) {
		return;
	}
	size_t hi_bit_mod = bll->hi_bit();
	size_t hi_bit_this = this->hi_bit();
	BitLL mod_temp = new BitLL(bll);
	mod_temp.rshift(hi_bit_this - hi_bit_mod);
	if (mod_temp > this) {
		mod_temp.lshift(1);
	}
	this->subtractSelf(&mod_temp);
	size_t count = 0;
	size_t hi_bit_mod_temp;
	
	while (!((*this) < bll)) {
		hi_bit_mod_temp = mod_temp.hi_bit();
		hi_bit_this = this->hi_bit();
		mod_temp.lshift(hi_bit_mod_temp - hi_bit_this );
		if (mod_temp > this) {
			mod_temp.lshift(1);

		}
		this->subtractSelf(&mod_temp);
		count++;
	}

	//delete mod_temp;
}

void BitLL::modMultSelf(BitLL *bll, BitLL *mod) {
	BitLL b = new BitLL(bll);
	b.modSelf(mod);
	this->modSelf(mod);
	this->multSelf(&b);
	this->modSelf(mod);
	//delete b;
}

void BitLL::modExpSelf(BitLL *exp, BitLL *mod) {
	// this = (this ^ exp) % mod
	size_t exp_hi_bit = exp->hi_bit();
	BitLL s = new BitLL(1);
	BitLLNode *n = exp->first;
	while (n != NULL) {
		if (n->val) {
			s.modMultSelf(this, mod);
		}
		this->modMultSelf(this, mod);
		n = n->next;
	}
	(*this) = &s;
	//delete s;
}

void BitLL::addSelf(BitLL *bll) {
	// carry = this & bll
	// result = this ^ bll
	BitLL carry = BitLL(this);
	//BitLL result = BitLL(this);
	carry.andSelf(bll);
	this->xorSelf(bll);//result.xorSelf(bll);
	carry.truncRight();
	
	while (carry.len > 0) {
		// Trying to avoid making a full copy of the carry list for the shift
		// BitLL shifted_carry = BitLL(carry);
		// in each loop:
		// shifted_carry = carry >> 1
		// result = resut ^ shfited_carry
		// carry = result & shifted_carry
		BitLLNode *c = carry.first;
		BitLLNode *r = this->first;
		bool last_c = 0;
		bool temp = 0;
		size_t carry_len = carry.len;
		for (size_t i = 0; i <= carry_len; i++) {
			if (r == NULL) {
				this->push(0);
				r = this->last;
			}
			if (c == NULL) {
				carry.push(0);
				c = carry.last;
			}
			temp = c->val;
			c->val = r->val & last_c;
			r->val = r->val ^ last_c;
			
			last_c = temp;
			c = c->next;
			r = r->next;
		}
		carry.truncRight();
	}
}

void BitLL::subtractSelf(BitLL *bll) {
	BitLL b = BitLL(bll);
	BitLL zero = BitLL();
	zero.push(0);
	// should be a way to avoid the two copy operations
	while (b.len > 0) {
		BitLL carry = BitLL(this);
		carry.notSelf();
		carry.andSelf(&b);
		this->xorSelf(&b);
		b = &carry;
		b.rshift(1);
		b.truncRight();
	}
	this->truncRight();
}

void BitLL::multSelf(BitLL *bll) {
	BitLL result = BitLL(); // 0
	result.push(0);
	BitLLNode *b = bll->first;
	size_t count = 0;
	while (b != NULL) {
		if (b->val == true) {
			result.addSelf(this);
		}
		this->rshift(1);
		b = b->next;
	}
	*this = &result;
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

size_t BitLL::uint64() {
	size_t result = 0;
	size_t index = 0;
	BitLLNode *n = this->first;
	while (n != NULL && index < 64) {
		result |= (n->val ? 1 : 0) << index;
		n = n->next;
		index++;
	}
	return result;
}

