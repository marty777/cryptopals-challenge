#include "Utility.h"
#include <assert.h>
#include <string>

std::string executable_relative_path(char *path) {
	std::string argv_str(__argv[0]);
	std::string base = argv_str.substr(0,argv_str.find_last_of("\\"));
	std::string finalpath = base.append(path);
	return finalpath;
}

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

// 
CURLcode libcurl_http_timed_response(CURL *curl, std::string url, long long *duration, long *responsecode, int numtrials) {
	using namespace std::chrono;
	high_resolution_clock::time_point starttime, endtime;
	long long avgms = 0;

	CURLcode res;

	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, libcurl_write_data); // don't do anything with the response

	for (int i = 0; i < numtrials; i++) {

		starttime = high_resolution_clock::now();
		res = curl_easy_perform(curl);
		endtime = high_resolution_clock::now();

		if (res != CURLE_OK) {
			return res;
		}

		// not handling any changes in response code over the trials at the moment.
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, responsecode); 

		avgms += duration_cast<milliseconds>(endtime - starttime).count();
	}
	
	// don't bother averaging.
	*duration = avgms;
	return CURLE_OK;
}

void bv_concat(ByteVector *a, ByteVector *b, ByteVector *output) {
	assert(a != NULL);
	if (a == NULL && b == NULL) {
		output->resize(0);
		return;
	}
	if (b != NULL) {
		output->resize(a->length() + b->length());
		a->copyBytesByIndex(output, 0, a->length(), 0);
		b->copyBytesByIndex(output, 0, b->length(), a->length());
	}
	else {
		output->resize(a->length());
		a->copyBytesByIndex(output, 0, a->length(), 0);
	}
}