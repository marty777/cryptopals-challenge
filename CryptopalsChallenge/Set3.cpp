#include "Set3.h"
#include "ByteVector.h"
#include "ByteEncryption.h"
#include <iostream>


using namespace std;

void Set3Challenge17() {
	vector<ByteVector> strings;
	strings.resize(10);
	strings[0] = ByteVector("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", BASE64);
	strings[1] = ByteVector("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", BASE64);
	strings[2] = ByteVector("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", BASE64);
	strings[3] = ByteVector("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", BASE64);
	strings[4] = ByteVector("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", BASE64);
	strings[5] = ByteVector("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", BASE64);
	strings[6] = ByteVector("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", BASE64);
	strings[7] = ByteVector("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", BASE64);
	strings[8] = ByteVector("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", BASE64);
	strings[9] = ByteVector("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93", BASE64);
	
	ByteVector secretKey = ByteVector(16);
	ByteVector iv = ByteVector(16);
	secretKey.random();
	iv.random();
	
	ByteVector output = ByteVector();
	ByteEncryption::challenge17encrypt(&strings, &secretKey, &output, &iv, false);
	output.printHexStrByBlocks(16);
	cout << "Decryption padding valid: " << (ByteEncryption::challenge17paddingvalidate(&output, &secretKey, &iv) ? "true" : "false") << endl ;

}

int Set3() {
	cout << "### SET 3 ###" << endl;
	cout << "Set 3 Challenge 17" << endl;
	Set3Challenge17();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	return 0;
}