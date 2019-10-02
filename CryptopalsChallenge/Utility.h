#pragma once
#include "ByteVector.h" 
#include <chrono>
#include "curl.h"

byte byterotateleft(byte b, int shift);

byte byterotateright(byte b, int shift);

uint32_t int32rotateleft(uint32_t b, int shift);

uint32_t int32rotateright(uint32_t b, int shift);

// random signed int between start and end using rand()
int rand_range(int start, int end);

uint32_t int32reverseBytes(uint32_t in);

// Callback for libcurl
size_t libcurl_write_data(void *buffer, size_t size, size_t nmemb, void *userp);

// Gives response code and average response time of several identical GET requests
CURLcode libcurl_http_timed_response(CURL *curl, std::string url, long long *duration, long *responsecode, int numtrials = 3);