#pragma once
#include "ByteVector.h" 

byte byterotateleft(byte b, int shift);

byte byterotateright(byte b, int shift);

uint32_t int32rotateleft(uint32_t b, int shift);

uint32_t int32rotateright(uint32_t b, int shift);

// random signed int between start and end using rand()
int rand_range(int start, int end);
