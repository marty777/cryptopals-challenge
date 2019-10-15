#include "ByteVectorMath.h"
#include <iostream>
#include <assert.h>


ByteVectorMath::ByteVectorMath()
{
}
ByteVectorMath::ByteVectorMath(uint32_t a) {
	// least significant bits first
	this->resize(4);
	(*this)[0] = bitwiseReverse[0xff & (a)];
	(*this)[1] = bitwiseReverse[0xff & (a >> 8)];
	(*this)[2] = bitwiseReverse[0xff & (a >> 16)];
	(*this)[3] = bitwiseReverse[0xff & (a >> 24)];
}
ByteVectorMath::ByteVectorMath(ByteVector a, bool flip) {
	// least significant bits first
	this->resize(a.length());
	for (size_t i = 0; i < a.length(); i++) {
		if (flip) {
			(*this)[i] = bitwiseReverse[a[a.length() - 1 - i]];
		}
		else {
			(*this)[i] = a[i];
		}
	}
}

ByteVectorMath::~ByteVectorMath(){
}

size_t ByteVectorMath::bitlength() {
	return 8 * this->length();
}
size_t ByteVectorMath::hibit() {
	size_t index = this->bitlength() - 1;
	while (index > 0) {
		if (this->bitAtIndex(index) == 1) {
			return index;
		}
		index--;
	}
	return 0;
}
bool ByteVectorMath::bitAtIndex(size_t index) {
	if (index >= this->bitlength()) {
		return 0;
	}
	return (bool) (0x01 & ((*this)[index/8] >> (7 - (index % 8))));
}
void ByteVectorMath::setBitAtIndex(bool value, size_t index) {
	if (index >= this->bitlength()) {
		size_t start_len = this->length();
		size_t new_len = (index / 8) + 1;
		this->resize(new_len);
		for (size_t i = start_len; i < new_len; i++) {
			(*this)[i] = 0;
		}
	}
	if (value == 1) {
		(*this)[index / 8] |= 0x1 << (7 - (index % 8));
	}
	else {
		(*this)[index / 8] &= ~(0x1 << (7 - (index % 8)));
	}
}


void ByteVectorMath::operator = (ByteVectorMath b) {
	this->resize(b.length());
	b.copyBytesByIndex(this, 0, b.length(), 0);
}
bool ByteVectorMath::operator == (ByteVectorMath b) {
	ByteVector c = (*this) ^ b;
	c.truncateRight();
	return (c.length() == 0);
}
bool ByteVectorMath::operator < (ByteVectorMath b) {
	ByteVectorMath a = ByteVectorMath();
	a = (*this);
	a.truncateRight();
	b.truncateRight();
	if (a.length() < b.length()) {
		return true;
	}
	else if (a.length() > b.length()) {
		return false;
	}
	else {
		long long index = (a.length() - 1);
		while (index >= 0) {
			if (bitwiseReverse[a[index]] > bitwiseReverse[b[index]]) {
				return false;
			}
			else if (bitwiseReverse[a[index]] < bitwiseReverse[b[index]]) {
				return true;
			}
			// else continue;
			index--;
		}
		return false; // equal
	}
}
bool ByteVectorMath::operator > (ByteVectorMath b) {
	ByteVectorMath a = ByteVectorMath();
	a = (*this);
	a.truncateRight();
	b.truncateRight();
	if (a.length() < b.length()) {
		return false;
	}
	else if (a.length() > b.length()) {
		return true;
	}
	else {
		long long index = (a.length() - 1);
		while (index >= 0) {
			if (bitwiseReverse[a[index]] > bitwiseReverse[b[index]]) {
				return true;
			}
			else if (bitwiseReverse[a[index]] < bitwiseReverse[b[index]]) {
				return false;
			}
			// else continue;
			index--;
		}
		return false; // equal
	}
}

ByteVectorMath ByteVectorMath::operator >> (size_t n) {
	int bitshift = n % 8;
	size_t byteshift = n / 8;
	size_t final_len = this->length() + byteshift + (n > 0 ? 1 : 0);
	ByteVectorMath ret = ByteVectorMath(final_len);
	ret.allBytes(0);
	for (size_t i = 0; i < final_len - byteshift; i++) {
		ret[i + byteshift] = 0xff & ((*this)[i] >> bitshift);
		if (i > 0) {
			ret[i + byteshift] |= 0xff & ((*this)[i - 1] << (8 - bitshift));
		}
	}
	return ret;
}

ByteVectorMath ByteVectorMath::operator << (size_t n) {
	int bitshift = n % 8;
	size_t byteshift = n / 8;
	size_t final_len = this->length() - byteshift + 1;
	printf("<< %d %d %d\n", bitshift, byteshift, final_len);

	ByteVectorMath ret = ByteVectorMath(final_len);
	ret.allBytes(0);
	for (size_t i = 0; i < final_len; i++) {
		if (i + byteshift < this->length()) {
			ret[i] = 0xff & (*this)[i + byteshift] << bitshift;
		}
		else {
			ret[i] = 0;
		}
		if (i + byteshift + 1 < this->length()) {
			ret[i] |= 0xff & ((*this)[i + byteshift + 1] >> (8 - bitshift));
		}
	}
	return ret;
}

// slow, possibly leaky
void ByteVectorMath::addSelf(ByteVectorMath b) {
	ByteVector carry = (*this) & b;
	ByteVector result = (*this) ^ b;
	carry.truncateRight();
	ByteVectorMath zero = ByteVectorMath(0);
	size_t carry_rshift = 0;
	while (carry.length() > 0) {	
		ByteVector shiftedCarry = carry >> 1;
		
		carry = result & shiftedCarry;
		result.xorSelf(&shiftedCarry);
		carry.truncateRight();
	}
	result.truncateRight();
	this->resize(result.length());
	result.copyBytesByIndex(this, 0, result.length(), 0);
}

// Not sure this handles a negative result well
void ByteVectorMath::subtractSelf(ByteVectorMath b) {
	ByteVectorMath b1 = ByteVectorMath(b, false);
	b1.truncateRight();
	ByteVectorMath result = ByteVectorMath(this, false);
	ByteVectorMath zero = ByteVectorMath(0);
	while (!(b1 == zero)) {
		// carry = ~result & b1
		ByteVectorMath carry = ByteVectorMath(result, false);
		carry.notSelf();
		carry.andSelf(&b1);
		// result = result ^ b1
		result.xorSelf(&b1);
		b1 = carry;
		b1.rightShiftSelf(1);
		//b1.truncateRight();
	}
	*this = result;
}

void ByteVectorMath::subtractSelfLeftShift(ByteVectorMath b, size_t lshift_offset) {
	ByteVectorMath b1 = ByteVectorMath();
	size_t bit_offset = lshift_offset % 8;
	size_t byte_offset = lshift_offset / 8;
	b1.resize(b.length() - byte_offset);
	for (size_t i = 0; i < b1.length(); i++) {
		b1[i] = 0;
		if (i + byte_offset < b.length()) {
			b1[i] |= b[i + byte_offset] << (bit_offset);
		}
		if (i + byte_offset + 1 < b.length()) {
			b1[i] |= b[i + byte_offset + 1] << (7 - bit_offset);
		}
	}
	//...
}

void ByteVectorMath::multiplySelf(ByteVectorMath b) {
	// Russian peasant
	ByteVectorMath result = ByteVectorMath(0);
	size_t index = 0;
	size_t hi_bit_b = b.hibit();
	while (index <= hi_bit_b) {
		if (b.bitAtIndex(index) == 1) {
			result.addSelf(*this);
		}
		this->rightShiftSelf(1);
		index++;
	}
	(*this) = result;
}

void ByteVectorMath::divideSelf(ByteVectorMath b, ByteVectorMath *remainder) {
	ByteVectorMath b1 = ByteVectorMath();
	b1 = b;
	ByteVectorMath a1 = ByteVectorMath();
	a1 = (*this);
	a1.truncateRight();
	b1.truncateRight();
	assert(b1.length() > 0); // division by zero;
	if (a1.length() == 0) {
		// zero dividend
		remainder->resize(1);
		(*remainder)[0] = 0;
		return;
	}
	ByteVectorMath one = ByteVectorMath(1);
	if (b1 == one) {
		// quotient = this, remainder = 0
		remainder->allBytes(0);
		remainder->truncateRight();
		return;
	}
	if (a1 == b1) {
		// quotient = 1, remainder = 0
		remainder->allBytes(0); 
		remainder->truncateRight();
		this->allBytes(0);
		(*this)[0] = bitwiseReverse[0x01]; /// 1
		this->truncateRight();
		return;
	}
	if (a1 < b1) {
		// quotient = 0, remainder = this
		remainder->resize(this->length());
		this->copyBytesByIndex(remainder, 0, this->length(), 0);
		this->allBytes(0);
		this->truncateLeft();
		return;
	}

	ByteVectorMath q = ByteVectorMath(1);
	q.allBytes(0);
	size_t hi_bit = a1.hibit();
	
	ByteVectorMath acc = ByteVectorMath(0);
	ByteVectorMath rem = ByteVectorMath(a1, false);
	for (size_t i = 0; i <= hi_bit; i++) {
		//ByteVectorMath c = b1 >> (hi_bit - i);
		ByteVectorMath c = ByteVectorMath(b1, false);
		c.rightShiftSelf(hi_bit - i);
		ByteVectorMath d = ByteVectorMath(c, false);
		c.addSelf(acc);
		if (c < a1 || c == a1) {
			rem.subtractSelf(d);
			acc.addSelf(d);
			q.setBitAtIndex(1, (hi_bit - i));
		}
	}
	q.truncateRight();
	rem.truncateRight();
	this->resize(q.length());
	q.copyBytesByIndex(this, 0, q.length(), 0);
	remainder->resize(rem.length());
	rem.copyBytesByIndex(remainder, 0, rem.length(), 0);
}

void ByteVectorMath::exponentSelf(uint32_t power) {
	ByteVectorMath result = ByteVectorMath(1);
	ByteVectorMath x = ByteVectorMath();
	x.resize(this->length());
	this->copyBytesByIndex(&x, 0, this->length(), 0);
	ByteVectorMath y = ByteVectorMath(power);
	size_t y_hi_bit_index = y.hibit();
	size_t y_bit_index = 0;
	while (y_bit_index <= y_hi_bit_index) {
		// if y << index is odd
		if (y.bitAtIndex(y_bit_index) == 1) {
			result.multiplySelf(x);
		}
		x.multiplySelf(x); // x = x^2;
		y_bit_index++;
	}
	this->resize(result.length());
	result.copyBytesByIndex(this, 0, result.length(), 0);
}

void ByteVectorMath::modSelf(uint32_t mod) {
	ByteVectorMath dividend = ByteVectorMath(this, false);
	ByteVectorMath divisor = ByteVectorMath(mod);
	ByteVectorMath remainder = ByteVectorMath();
	dividend.divideSelf(divisor, &remainder);
	(*this) = remainder;
	
}

void ByteVectorMath::modSelf1(ByteVectorMath mod) {
	if ((*this) < mod) {
		return;
	}
	ByteVectorMath dividend = ByteVectorMath(this, false);
	ByteVectorMath divisor = ByteVectorMath(mod, false);
	ByteVectorMath remainder = ByteVectorMath();
	dividend.divideSelf(divisor, &remainder);
	(*this) = remainder;
}

void ByteVectorMath::modSelf(ByteVectorMath *mod) {
	if ((*this) < (*mod)) {
		return;
	}
	size_t hi_bit_mod = mod->hibit();
	size_t hi_bit_this = this->hibit();
	ByteVectorMath mod_temp = ByteVectorMath(mod, false);
	mod_temp.rightShiftSelf((hi_bit_this - hi_bit_mod));
	if (mod_temp > (*this)) {
		mod_temp.leftShiftSelf(1);
	}
	(*this).subtractSelf(mod_temp);
	size_t count = 0;
	size_t hi_bit_mod_temp;

	while (!((*this) < (*mod))) {
		hi_bit_mod_temp = mod_temp.hibit();
		hi_bit_this = this->hibit();
		mod_temp.leftShiftSelf(hi_bit_mod_temp - hi_bit_this);
		if (mod_temp > (*this)) {
			mod_temp.leftShiftSelf(1);
			//printf("leftshift\n");
		}
		this->subtractSelf(mod_temp);
		//printf("count %d\n", count);
		count++;
	}
}

void ByteVectorMath::modMultSelf(ByteVectorMath *b, ByteVectorMath *mod) {
	ByteVectorMath b1 = ByteVectorMath(b, false);
	b1.modSelf(mod);
	this->modSelf(mod);
	this->multiplySelf(b1);
	this->modSelf(mod);
}

void ByteVectorMath::modExpSelf(uint32_t exp, uint32_t mod) {
	ByteVectorMath exp1 = ByteVectorMath(exp);
	ByteVectorMath mod1 = ByteVectorMath(mod);
	this->modExpSelf(exp1, mod1);
}

void ByteVectorMath::modExpSelf(ByteVectorMath exp, ByteVectorMath mod) {
	// this = (this ^ exp) % mod
	ByteVectorMath temp = ByteVectorMath(this, false);
	ByteVectorMath exp1 = ByteVectorMath(exp, false);
	ByteVectorMath mod1 = ByteVectorMath(mod, false);
	ByteVectorMath s = ByteVectorMath(1);
	size_t max_exp_bit = exp1.hibit();
	printf("exp1 hibit: %d\n", max_exp_bit);
	size_t exp_index = 0;
	while (exp_index <= max_exp_bit) {
		printf("loop exp1 index: %d\n", exp_index);
		if (exp1.bitAtIndex(exp_index) == 1) {
			printf("bit1\n", exp_index);
			s.modMultSelf(&temp, &mod1);
		}
		temp.modMultSelf(&temp, &mod1);
		exp_index++;
	}
	(*this) = s;
}

byte ByteVectorMath::byteReverse(byte b) {
	return bitwiseReverse[b];
}

// only works with first 64 bits
size_t ByteVectorMath::uint64val() {
	if (this->length() == 0) {
		return 0;
	}
	size_t result = 0;
	for (size_t i = 0; i < this->length() && i < 8; i++) {
		result |= bitwiseReverse[(*this)[i]] << (i * 8);
	}
	return result;
}

// sets vector to random value on 0..modulus-1 using rand()
void ByteVectorMath::random(ByteVectorMath modulus) {
	ByteVectorMath m = ByteVectorMath(modulus, false);
	m.truncateRight();
	this->resize(m.length());
	for (size_t i = 0; i < m.length(); i++) {
		(*this)[i] = (byte)(rand() % 256);
	}
	this->modSelf(&m);
}
