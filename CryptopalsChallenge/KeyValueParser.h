#pragma once
//#include <map>
#include <string>
#include <utility>
#include "ByteVector.h"
class KeyValueParser
{
private:
	std::vector<std::pair<std::string, std::string>> _keyvals;
public:
	KeyValueParser();
	~KeyValueParser();

	std::string valueWithKey(std::string key);

	// return false on parsing failure
	bool parseDelimited(std::string input);
	bool parseDelimited(ByteVector *input);
	std::string toDelimitedString();
	void profile_for(ByteVector *input, ByteVector *output);
	void encrypt_profile_for(ByteVector *input, ByteVector *key, ByteVector *output);
	void decrypt_profile_for(ByteVector *input, ByteVector *key);
};

