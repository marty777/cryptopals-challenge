#include "uint64VectorMath.h"



uint64VectorMath::uint64VectorMath()
{
}


uint64VectorMath::~uint64VectorMath()
{
}

uint64VectorMath::uint64VectorMath(uint64VectorMath *a) {
	this->resize(a->length());
	for (size_t i = 0; i < a->length(); i++) {
		(*this)[i] = (*a)[i];
	}
}
uint64VectorMath::uint64VectorMath(uint64_t a) {
	this->resize(1);
	(*this)[0] = a;
}
uint64VectorMath::uint64VectorMath(ByteVector *a) {
	if (a->length() % 8 == 0) {
		this->resize(a->length() / 8);
	}
	else {
		this->resize((a->length() / 8) + 1);
	}
	uint64_t temp = 0;
	for (size_t i = 0; i < a->length(); i++) {
		temp |= (uint64_t)((*a)[i]) << 8 * ((7 - i) % 8);
		if (i % 8 == 7) {
			(*this)[this->length() - 1 - (i / 8)] = temp;
			temp = 0;
		}
	}
	if (a->length() % 8 != 0) {
		(*this)[0] = temp;
	}
}

uint64_t uint64VectorMath::operator[] (size_t n) const {
	return _v[n];
}
uint64_t& uint64VectorMath::operator [] (size_t n) {
	return _v[n];
}

uint64VectorMath uint64VectorMath::operator >> (size_t n) {
	size_t byteshift = n / 64;
	size_t bitshift = n % 64;
	size_t final_len = this->length() - byteshift + 1;
	uint64VectorMath m = uint64VectorMath();
	m.resize(final_len);
	for (size_t i = 0; i < final_len; i++) {
		uint64_t prev;
		if (i + byteshift < this->length()) {
			m[i] = 0xffffffffffffffff & (*this)[i + byteshift] >> bitshift;
		}
		else {
			m[i] = 0;
		}
		if (i + byteshift + 1 < this->length()) {
			m[i] |= 0xffffffffffffffff & ((*this)[i + byteshift + 1] << (64 - bitshift));
		}
	}
	m.truncLeft();
	return m;
}
uint64VectorMath uint64VectorMath::operator << (size_t n) {
	size_t byteshift = n / 64;
	size_t bitshift = n % 64;
	size_t final_len = this->length() + byteshift + 1;
	uint64VectorMath m = uint64VectorMath();
	m.resize(final_len);
	for (size_t i = 0; i < m.length(); i++) {
		m[i] = 0;
	}
	for (size_t i = byteshift; i < this->length() + 1; i++) {
		if (i < this->length() + byteshift) {
			m[i] = 0xffffffffffffffff & (*this)[i - byteshift] << bitshift;
		}
		if (i >= byteshift+1) {
			m[i] |= 0xffffffffffffffff & ((*this)[i - byteshift - 1] >> (63 - bitshift));
		}
	}
	m.truncLeft();
	return m;
}
uint64VectorMath uint64VectorMath::operator & (uint64VectorMath b) {
	size_t len = this->length();
	if (b.length() > len) {
		len = b.length();
	}
	uint64VectorMath m = uint64VectorMath();
	m.resize(len);
	uint64_t c, d;
	for (size_t i = 0; i < len; i++) {
		c = 0;
		d = 0;
		if (i < this->length()) {
			c = (*this)[i];
		}
		if (i < b.length()) {
			d = b[i];
		}
		m[i] = c & d;
	}
	return m;
}
uint64VectorMath uint64VectorMath::operator | (uint64VectorMath b) {
	size_t len = this->length();
	if (b.length() > len) {
		len = b.length();
	}
	uint64VectorMath m = uint64VectorMath();
	m.resize(len);
	uint64_t c, d;
	for (size_t i = 0; i < len; i++) {
		c = 0;
		d = 0;
		if (i < this->length()) {
			c = (*this)[i];
		}
		if (i < b.length()) {
			d = b[i];
		}
		m[i] = c | d;
	}
	return m;
}
uint64VectorMath uint64VectorMath::operator ^ (uint64VectorMath b) {
	size_t len = this->length();
	if (b.length() > len) {
		len = b.length();
	}
	uint64VectorMath m = uint64VectorMath();
	m.resize(len);
	uint64_t c, d;
	for (size_t i = 0; i < len; i++) {
		c = 0;
		d = 0;
		if (i < this->length()) {
			c = (*this)[i];
		}
		if (i < b.length()) {
			d = b[i];
		}
		m[i] = c ^ d;
	}
	return m;
}
uint64VectorMath uint64VectorMath::operator ~ () {
	uint64VectorMath m = uint64VectorMath(this);
	for (size_t i = 0; i < this->length(); i++) {
		m[i] = ~(m[i]);
	}
	return m;
}

bool uint64VectorMath::operator == (uint64VectorMath b) {
	uint64VectorMath c = (*this) ^ b;
	c.truncLeft();
	return (c.length() == 0);
}
bool uint64VectorMath::operator != (uint64VectorMath b) {
	uint64VectorMath c = (*this) ^ b;
	c.truncLeft();
	return (c.length() != 0);
}
bool uint64VectorMath::operator > (uint64VectorMath b) {
	uint64VectorMath a = uint64VectorMath(this);
	a.truncLeft();
	b.truncLeft();
	if (a.length() < b.length()) {
		return false;
	}
	else if (a.length() > b.length()) {
		return true;
	}
	size_t index = a.length() - 1;
	while (index > 0) {
		if (a[index] > b[index]) {
			return true;
		}
		else if (a[index] < b[index]) {
			return false;
		}
		index--;
	}
	if (a[0] > b[0]) {
		return true;
	}
	return false;
}
bool uint64VectorMath::operator < (uint64VectorMath b) {
	uint64VectorMath a = uint64VectorMath(this);
	a.truncLeft();
	b.truncLeft();
	if (a.length() < b.length()) {
		return true;
	}
	else if (a.length() > b.length()) {
		return false;
	}
	size_t index = a.length() - 1;
	while (index > 0) {
		if (a[index] > b[index]) {
			return false;
		}
		else if (a[index] < b[index]) {
			return true;
		}
		index--;
	}
	if (a[0] < b[0]) {
		return true;
	}
	return false;
}

void uint64VectorMath::resize(size_t len) {
	_v.resize(len);
}
void uint64VectorMath::reserve(size_t len) {
	_v.reserve(len);
}
size_t uint64VectorMath::length() {
	return _v.size();
}

// returns index of 1 if this is zero
size_t uint64VectorMath::hibit() {
	for (size_t i = this->length() - 1; i > 0; i--) {
		if ((*this)[i] == 0) {
			continue;
		}
		for (int j = 63; j >= 0; j++) {
			if ((0x1 & (*this)[i] >> (63 - j)) != 0) {
				return (64 * i + j);
			}
			
		}
	}
	for (int j = 63; j >= 0; j++) {
		if ((0x1 & (*this)[0] >> (63 - j)) != 0) {
			return (j);
		}
	}
	return 1;
}

void uint64VectorMath::truncLeft() {
	size_t i = this->length() - 1;
	while (i > 0) {
		if ((*this)[i] != 0) {
			break;
		}
		i--;
	}
	this->resize(i + 1);
}

void uint64VectorMath::lshiftSelf(size_t shift) {
	uint64VectorMath m = (*this) << shift;
	this->copyToSelf(&m);
}
void uint64VectorMath::rshiftSelf(size_t shift) {
	uint64VectorMath m = (*this) >> shift;
	this->copyToSelf(&m);
}

bool uint64VectorMath::getBit(size_t index) {
	return (bool) (0x1 & (*this)[index / 64] >> (index % 64));
}
void uint64VectorMath::setBit(bool val, size_t index) {
	uint64_t mask = ((uint64_t)0x1) << (index % 64);
	if (val == 0) {
		(*this)[index / 64] &= ~mask;
	}
	else {
		(*this)[index / 64] |= mask;
	}
}

void uint64VectorMath::notSelf() {
	for (size_t i = 0; i < this->length(); i++) {
		(*this)[i] = ~((*this)[i]);
	}
}
void uint64VectorMath::andSelf(uint64VectorMath *b) {
	size_t len = this->length();
	size_t start_len = len;
	if (len < b->length()) {
		len = b->length();
		this->resize(len);
	}
	for (size_t i = 0; i < len; i++) {
		uint64_t word = 0;
		if (i <= start_len) {
			word = (*this)[i];
		}
		if (i < b->length()) {
			word &= (*b)[i];
		}
		else {
			word &= 0;
		}
		(*this)[i] = word;
	}
}
void uint64VectorMath::orSelf(uint64VectorMath *b) {
	size_t len = this->length();
	size_t start_len = len;
	if (len < b->length()) {
		len = b->length();
		this->resize(len);
	}
	for (size_t i = 0; i < len; i++) {
		uint64_t word = 0;
		if (i <= start_len) {
			word = (*this)[i];
		}
		if (i < b->length()) {
			word |= (*b)[i];
		}
		else {
			word |= 0;
		}
		(*this)[i] = word;
	}
}
void uint64VectorMath::xorSelf(uint64VectorMath *b) {
	size_t len = this->length();
	size_t start_len = len;
	if (len < b->length()) {
		len = b->length();
		this->resize(len);
	}
	for (size_t i = 0; i < len; i++) {
		uint64_t word = 0;
		if (i <= start_len) {
			word = (*this)[i];
		}
		if (i < b->length()) {
			word ^= (*b)[i];
		}
		else {
			word ^= 0;
		}
		(*this)[i] = word;
	}
}

void uint64VectorMath::copyToSelf(uint64VectorMath *b) {
	this->resize(b->length());
	for (size_t i = 0; i < b->length(); i++) {
		(*this)[i] = (*b)[i];
	}
}

void uint64VectorMath::addSelf(uint64VectorMath *b) {
	size_t initial_len = this->length();
	size_t final_len = initial_len;
	if (final_len < b->length()) {
		final_len = b->length();
	}
	final_len++;
	this->resize(final_len);
	uint64_t carry = 0;
	for (size_t i = 0; i < final_len; i++) {
		uint64_t c, d, final_bit_c, final_bit_d, sum, final_bit;
		if (i < initial_len) {
			c = 0x7fffffffffffffff & (*this)[i];
			final_bit_c = 0x1 & ((*this)[i] >> 63);
		}
		else {
			c = 0;
			final_bit_c = 0;
		}
		if (i < b->length()) {
			d = 0x7fffffffffffffff & (*b)[i];
			final_bit_d = 0x1 & ((*b)[i] >> 63);
		}
		else {
			d = 0;
			final_bit_d = 0;
		}
		sum = c + d + carry;
		final_bit = (0x1 & (sum >> 63)) + final_bit_c + final_bit_d;
		sum = (sum & 0x7fffffffffffffff) | ((0x1 & final_bit) << 63);
		(*this)[i] = sum;
		carry = 0x1 & (final_bit >> 1);
	}
}


void uint64VectorMath::subtractSelf(uint64VectorMath *b) {
	uint64VectorMath b1 = uint64VectorMath(b);
	b1.truncLeft();
	uint64VectorMath zero = uint64VectorMath();
	zero.resize(1);
	zero[0] = 0;
	while (b1 != zero) {
		// carry = ~result & b1
		uint64VectorMath carry = uint64VectorMath(this);
		carry.notSelf();
		carry.andSelf(&b1);
		// result = result ^ b1
		this->xorSelf(&b1);
		b1.copyToSelf(&carry);
		b1.lshiftSelf(1);
	}
}

void uint64VectorMath::divideSelf(uint64VectorMath *b, uint64VectorMath *remainder) {
	//uint64VectorMath dividend = uint64VectorMath(this);
	//uint64VectorMath divisor = uint64VectorMath(b);
	//uint64VectorMath quotient = uint64VectorMath();
	//uint64VectorMath rem = uint64VectorMath();

	//// Easy cases
	//// quotient 0, remainder dividend
	//if (dividend < divisor) {
	//	remainder->copyToSelf(this);
	//	this->resize(1);
	//	(*this)[0] = (uint64_t)0;
	//	return;
	//}
	//// quotient 1, remainder 0
	//else if (dividend == divisor) {
	//	remainder->resize(1);
	//	(*remainder)[0] = (uint64_t)0;
	//	this->resize(1);
	//	(*this)[0] = (uint64_t)1;
	//	return;
	//}


}
void uint64VectorMath::modSelf(uint64VectorMath *mod) {
	if ((*this) < (*mod)) {
		return;
	}
	size_t hi_bit_mod = mod->hibit();
	size_t hi_bit_this = this->hibit();
	uint64VectorMath mod_temp = uint64VectorMath(mod);
	mod_temp.lshiftSelf((hi_bit_this - hi_bit_mod));
	if (mod_temp > (*this)) {
		mod_temp.rshiftSelf(1);
	}
	(*this).subtractSelf(&mod_temp);
	size_t count = 0;
	size_t hi_bit_mod_temp;
	//while (!((*this) < (*mod))) {
	//	hi_bit_mod_temp = mod_temp.hibit();
	//	hi_bit_this = this->hibit();
	//	mod_temp.leftShiftSelf(hi_bit_mod_temp - hi_bit_this);
	//	if (mod_temp > (*this)) {
	//		mod_temp.leftShiftSelf(1);
	//		//printf("leftshift\n");
	//	}
	//	this->subtractSelf(mod_temp);
	//	//printf("count %d\n", count);
	//	count++;
	//}
	
}
void uint64VectorMath::modMultSelf(uint64VectorMath *b, uint64VectorMath *mod) {

}
void uint64VectorMath::modExpSelf(uint64VectorMath *exp, uint64VectorMath *mod) {

}


uint64_t uint64VectorMath::uint64val(size_t index) {
	if (index >= this->length()) {
		return 0;
	}
	else {
		return (*this)[index];
	}
}

void uint64VectorMath::printHex() {
	for (size_t i = 0; i < this->length(); i++) {
		/*printf("%d:\t", i);
		for (int j = 0; j < 2; j++) {
			uint32_t temp = (uint32_t)(0xffffffff & ((*this)[i] >> (32 * j)));
			printf("%08x", temp);
		}
		printf("\n");*/
		printf("%d:\t%016llx\n", i, (*this)[i]);
	}
}

void uint64VectorMath::copyToByteVector(ByteVector *bv) {
	bv->resize(this->length() * 8);
	for (size_t i = 0; i < this->length(); i++) {
		//temp |= (uint64_t)((*a)[i]) << 8 * (i % 8);
		for (int j = 0; j < 8; j++) {
			(*bv)[i*8 + j]= (byte)(0xff & (*this)[i] >> (j * 8));
		}
	}
}