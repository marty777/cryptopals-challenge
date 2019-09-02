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
	bool parseDelimited(std::string input, byte field_delimiter = '&', byte key_value_delimiter = '=');
	bool parseDelimited(ByteVector *input, byte field_delimiter = '&', byte key_value_delimiter = '=');
	std::string toDelimitedString(byte field_delimiter = '&', byte key_value_delimiter = '=');
	// for challenge 13
	void profile_for(ByteVector *input, ByteVector *output);
	void encrypt_profile_for(ByteVector *input, ByteVector *key, ByteVector *output);
	void decrypt_profile_for(ByteVector *input, ByteVector *key);
};

