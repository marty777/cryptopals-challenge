#include "Utility.h"
#include <assert.h>


byte byterotateleft(byte b, int shift) {
	return (b << shift) | (b >> 8 - shift);
}

byte byterotateright(byte b, int shift) {
	return (b >> shift) | (b << 8 - shift);
}

uint32_t int32rotateleft(uint32_t b, int shift) {
	return (b << shift) | (b >> 32 - shift);
}

uint32_t int32rotateright(uint32_t b, int shift) {
	return (b >> shift) | (b << 32 - shift);
}

// random signed int between start and end using rand()
int rand_range(int start, int end) {
	assert(end > start);
	return start + (rand() % (1 + end - start));
}
