#include "KeyValueParser.h"
#include <string>
#include <map>
#include <iostream>
#include "ByteEncryption.h"

using namespace std;
KeyValueParser::KeyValueParser()
{
}


KeyValueParser::~KeyValueParser()
{
}

std::string KeyValueParser::valueWithKey(std::string key) {
	for (size_t i = 0; i < _keyvals.size(); i++) {
		if (_keyvals[i].first == key) {
			return _keyvals[i].second;
		}
	}
	return "";
}

// clear current key/value contents and replace with parsed string
bool KeyValueParser::parseDelimited(std::string input, byte field_delimiter, byte key_value_delimiter) {
	_keyvals.clear();
	// ampersand delimited key-val pairs  e.g. foo=bar&baz=qux&zap=zazzle
	char delimiter = field_delimiter;
	char splitter = key_value_delimiter;
	// split on &
	vector<string> pairs;
	size_t last_pos = 0;
	size_t pos = 0;
	while ((pos = input.find(delimiter, pos)) != input.npos) {
		string substring(input.substr(last_pos, pos - last_pos));
		pairs.push_back(substring);
		pos++;
		last_pos = pos;
	}
	pairs.push_back(input.substr(last_pos, pos - last_pos));
	for (size_t i = 0; i < pairs.size(); i++) {
		// splitter must appear exactly once and have at least one byte to the left of it.
		// permit empty values but not empty keys.
		size_t splitter_count = std::count(pairs[i].begin(), pairs[i].end(), splitter);
		if (splitter_count != 1) {
			continue;
		}
		size_t position = pairs[i].find(splitter, 0);
		if (position == 0) {
			continue;
		}
		string key(pairs[i].substr(0, position));
		string val(pairs[i].substr(position + 1, pairs[i].length() - position + 1));
		_keyvals.push_back(pair<string, string>(key, val));
	}
	return true; 

}
bool KeyValueParser::parseDelimited(ByteVector *input, byte field_delimiter, byte key_value_delimiter) {
	ByteVector stripped = ByteVector();
	ByteEncryptionError err;
	string inputStr;
	if (ByteEncryption::pkcs7PaddingValidate(input, &stripped, &err)) {
		inputStr = string(stripped.toStr(ASCII));
	}
	else {
		inputStr = input->toStr(ASCII);
	}
	return parseDelimited(inputStr, field_delimiter, key_value_delimiter);
}

std::string KeyValueParser::toDelimitedString(byte field_delimiter, byte key_value_delimiter) {
	
	char delimiter = field_delimiter;
	char splitter = key_value_delimiter;
	size_t len = 0;

	for (size_t i = 0; i < _keyvals.size(); i++) {
		len += _keyvals[i].first.length() + 1 + _keyvals[i].second.length();
	}
	if (_keyvals.size() > 1) {
		len += (_keyvals.size() - 1);
	}

	string outString = "";
	outString.reserve(len);
	
	for (size_t i = 0; i < _keyvals.size(); i++) {
		outString += _keyvals[i].first + splitter +_keyvals[i].second;
		if (i < _keyvals.size() - 1) {
			outString += delimiter;
		}
	}
	return outString;
}

void KeyValueParser::profile_for(ByteVector *input, ByteVector *output) {

	char delimiter = '&';
	char splitter = '=';
	string inputStr = "email=";
	inputStr.reserve(input->length() + inputStr.length());
	// filter out any control characters
	for (size_t i = 0; i < input->length(); i++) {
		if (input->atIndex(i) == splitter || input->atIndex(i) == delimiter) {
			continue;
		}
		inputStr += input->atIndex(i);
	}
	inputStr += "&uid=10&role=user";
	this->parseDelimited(inputStr);
	string outStr = this->toDelimitedString();
	output->resize(outStr.length());
	for (size_t i = 0; i < outStr.length(); i++) {
		output->setAtIndex(outStr[i], i);
	}
}

void KeyValueParser::encrypt_profile_for(ByteVector *input, ByteVector *key, ByteVector *output) {
	ByteVector plaintextProfile = ByteVector();
	this->profile_for(input, &plaintextProfile);

	// pad profile text to blocksize
	ByteEncryption::pkcs7Pad(&plaintextProfile, 16);
	size_t block_size = 16;
	output->resize(plaintextProfile.length());
	ByteEncryption::aes_ecb_encrypt(&plaintextProfile, key, output, 0, plaintextProfile.length() - 1, true);
}
void KeyValueParser::decrypt_profile_for(ByteVector *input, ByteVector *key) {
	ByteVector decrypted = ByteVector(input->length());
	ByteEncryption::aes_ecb_encrypt(input, key, &decrypted, 0, input->length() - 1, false);
	this->parseDelimited(&decrypted);
}