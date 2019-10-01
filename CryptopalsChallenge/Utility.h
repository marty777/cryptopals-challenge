#pragma once
#include "ByteVector.h" 

byte byterotateleft(byte b, int shift);

byte byterotateright(byte b, int shift);

uint32_t int32rotateleft(uint32_t b, int shift);

uint32_t int32rotateright(uint32_t b, int shift);

// random signed int between start and end using rand()
int rand_range(int start, int end);

uint32_t int32reverseBytes(uint32_t in);

// Callback for libcurl
size_t libcurl_write_data(void *buffer, size_t size, size_t nmemb, void *userp);