#include "Utility.h"
#include <assert.h>


byte byterotateleft(byte b, int shift) {
	return (b << shift) | (b >> (8 - shift));
}

byte byterotateright(byte b, int shift) {
	return (b >> shift) | (b << (8 - shift));
}

uint32_t int32rotateleft(uint32_t b, int shift) {
	return (b << shift) | (b >> (32 - shift));
}

uint32_t int32rotateright(uint32_t b, int shift) {
	return (b >> shift) | (b << (32 - shift));
}

// random signed int between start and end using rand()
int rand_range(int start, int end) {
	assert(end > start);
	return start + (rand() % (1 + end - start));
}


uint32_t int32reverseBytes(uint32_t in) {
	byte b0 = (byte)0xff & (in >> 24);
	byte b1 = (byte)0xff & (in >> 16);
	byte b2 = (byte)0xff & (in >> 8);
	byte b3 = (byte)0xff & (in);
	return ((uint32_t)b3 << 24) | ((uint32_t)b2 << 16) | ((uint32_t)b1 << 8) | ((uint32_t)b0);
}


size_t libcurl_write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
	// dummy function. We don't actually do anything with the buffer.
	return size * nmemb;
}