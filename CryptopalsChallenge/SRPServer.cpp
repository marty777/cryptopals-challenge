#include "SRPServer.h"
#include "BNUtility.h"
#include "Utility.h"
#include "ByteEncryption.h"
#include <iostream>
#include <fstream>
#include <string>

SRPServer::SRPServer(BIGNUM *N, BIGNUM *g, BIGNUM *k, char *email, char *password, bool simple, bool mitm) {
	init_err = false;
	_ctx = BN_CTX_new();
	_N = BN_dup(N);
	_g = BN_dup(g);
	_k = BN_dup(k);
	
	if (mitm) { // mitm server shouldn't know email or password initially
		_I = ByteVector();
		_P = ByteVector();
	}
	else {
		_I = ByteVector(email, ASCII);
		_P = ByteVector(password, ASCII);
	}

	// challenge 38
	_simple = simple;
	_mitm = mitm;

	_salt = BN_new();

	if (!BN_rand(_salt, 64, -1, 0)) { // random 64 bit integer
		std::cerr << "Error initializing salt in SRPServer" << std::endl;
		init_err = true;
		return;
	}

	_v = NULL;

	if (!mitm) {
		// generate sha256 hash of salt + password
		ByteVector pwBV = ByteVector(password, ASCII);
		ByteVector saltBV = ByteVector();
		bn_to_bytevector(_salt, &saltBV);
		ByteVector saltedPW = ByteVector(saltBV.length() + pwBV.length());
		saltBV.copyBytesByIndex(&saltedPW, 0, saltBV.length(), 0);
		pwBV.copyBytesByIndex(&saltedPW, 0, pwBV.length(), saltBV.length());
		ByteVector hash = ByteVector();
		ByteEncryption::sha256(&saltedPW, &hash);

		// convert pw hash to BN integer
		BIGNUM *x = bn_from_bytevector(&hash);

		// v = g ^ x % N
		_v = BN_new();
		if (!BN_mod_exp(_v, _g, x, _N, _ctx)) {
			std::cerr << "Error computing v in SRPServer" << std::endl;
			BN_free(x);
			init_err = true;
			return;
		}
		BN_free(x);
	}

	_state = 0;
	_b = BN_new();
	BN_rand_range(_b, _N);


	_simple_u = NULL;
	_B = BN_new();
	if (_simple) {
		if (!BN_mod_exp(_B, _g, _b, _N, _ctx)) {
			std::cerr << "Error computing simple public key in SRPServer" << std::endl;
			init_err = true;
			return;
		}
		_simple_u = BN_new();
		if (!BN_rand(_simple_u, 128, -1, 0)) {
			std::cerr << "Error generating simple u value in SRPServer" << std::endl;
			init_err = true;
			return;
		}
	}
	else {
		BIGNUM *temp = BN_new();
		if (!BN_mod_exp(temp, _g, _b, _N, _ctx)) {
			std::cerr << "Error computing public key in SRPServer" << std::endl;
			BN_free(temp);
			init_err = true;
			return;
		}
		BIGNUM *kv = BN_new();
		if (!BN_mod_mul(kv, _k, _v, _N, _ctx)) {
			std::cerr << "Error computing public key in SRPServer" << std::endl;
			BN_free(kv);
			BN_free(temp);
			init_err = true;
			return;
		}
		if (!BN_mod_add(_B, kv, temp, _N, _ctx)) {
			std::cerr << "Error computing public key in SRPServer" << std::endl;
			BN_free(kv);
			BN_free(temp);
			init_err = true;
			return;
		}
		BN_free(kv);
		BN_free(temp);
	}
	
	
	_A = NULL;
	_S = NULL;

	
}


SRPServer::~SRPServer() {
	BN_CTX_free(_ctx);
	BN_free(_N);
	BN_free(_g);
	BN_free(_k);
	BN_free(_salt);
	if (_v != NULL) {
		BN_free(_v);
	}
	BN_free(_b);
	BN_free(_B);
	if (_A != NULL) {
		BN_free(_A);
	}
	if (_S != NULL) {
		BN_free(_S);
	}
	if (_simple_u != NULL) {
		BN_free(_simple_u);
	}
}

SRP_message SRPServer::response(SRP_message input) {
	SRP_message response;
	response.num_items = 0;
	response.first_item_len = 0;
	response.data = ByteVector();

	if (input.special == -1) {
		_state = 0;
		response.num_items = 0;
		response.special = OK;
		return response;
	}
	switch (_state) {
	case 0: // waiting for client email and public key
		return key_exchange(input);
		break;
	case 1: // waiting for client HMAC
		return hmac_validation(input);
		break;
	}
}

SRP_message SRPServer::key_exchange(SRP_message input) {
	std::vector<BIGNUM *> bn_ptrs;

	SRP_message response;
	response.num_items = 0;
	response.first_item_len = 0;
	response.data = ByteVector();

	ByteVector I = ByteVector();
	ByteVector A = ByteVector();
	ByteVector HMAC = ByteVector();

	ByteVector saltBV = ByteVector();
	ByteVector BBV = ByteVector();
	ByteVector ABV = ByteVector();
	ByteVector uH = ByteVector();

	BIGNUM *u;

	size_t temp;
	if (input.special != EXCHANGE_KEYS) {
		response.special = NOTOK;
		return response;
	}
	if (input.num_items != 2) {
		response.special = NOTOK;
		return response;
	}
	if (input.first_item_len == 0) {
		response.special = NOTOK;
		return response;
	}
	I.resize(input.first_item_len);
	A.resize(input.data.length() - input.first_item_len);
	input.data.copyBytesByIndex(&I, 0, input.first_item_len, 0);
	input.data.copyBytesByIndex(&A, input.first_item_len, input.data.length() - input.first_item_len, 0);

	if(_mitm) {
		I.duplicate(&_I);
	}
	else {
		if (!I.equal(&_I)) {
			response.special = NOTOK;
			return response;
		}
	}

	_A = bn_from_bytevector(&A);
	
	// compute uH, u
	bn_to_bytevector(_A, &ABV);
	bn_to_bytevector(_B, &BBV);

	temp = ABV.length();
	ABV.resize(ABV.length() + BBV.length());
	BBV.copyBytesByIndex(&ABV, 0, BBV.length(), temp);
	ByteEncryption::sha256(&ABV, &uH);
	u = bn_from_bytevector(&uH, &bn_ptrs);

	_S = BN_new();
	BIGNUM *temp1 = BN_new();
	BIGNUM *temp2 = BN_new();
	bn_add_to_ptrs(temp1, &bn_ptrs);
	bn_add_to_ptrs(temp2, &bn_ptrs);

	// generate S = (A*(v^u))^b % N
	if (!_mitm) {
		if (_simple) {
			if (!BN_mod_exp(temp1, _v, _simple_u, _N, _ctx)) {
				response.special = ERR;
				bn_free_ptrs(&bn_ptrs);
				return response;
			}
		}
		else {
			if (!BN_mod_exp(temp1, _v, u, _N, _ctx)) {
				response.special = ERR;
				bn_free_ptrs(&bn_ptrs);
				return response;
			}
		}
		if (!BN_mod_mul(temp2, _A, temp1, _N, _ctx)) {
			response.special = ERR;
			bn_free_ptrs(&bn_ptrs);
			return response;
		}
		if (!BN_mod_exp(_S, temp2, _b, _N, _ctx)) {
			response.special = ERR;
			bn_free_ptrs(&bn_ptrs);
			return response;
		}
	}

	bn_free_ptrs(&bn_ptrs);
	if (_simple) {
		bn_to_bytevector(_salt, &saltBV);
		bn_to_bytevector(_simple_u, &uH);
		ByteVector temp = ByteVector();
		bv_concat(&saltBV, &BBV, &temp);
		bv_concat(&temp, &uH, &response.data);
		response.num_items = 3;
		response.first_item_len = saltBV.length();
		response.second_item_len = BBV.length();
	}
	else {
		bn_to_bytevector(_salt, &saltBV);
		bv_concat(&saltBV, &BBV, &response.data);
		response.num_items = 2;
		response.first_item_len = saltBV.length();
	}
	_state = 1;
	response.special = EXCHANGE_KEYS;
	return response;
}

SRP_message SRPServer::hmac_validation(SRP_message input) {
	SRP_message response;
	response.num_items = 0;
	response.first_item_len = 0;
	response.data = ByteVector();

	if (_S == NULL) {
		response.special = ERR;
		return response;
	}
	if (input.special != HMAC_VERIFY) {
		response.special = NOTOK;
		return response;
	}
	if (input.num_items != 1) {
		response.special = NOTOK;
		return response;
	}
	if (input.first_item_len == 0) {
		response.special = NOTOK;
		return response;
	}

	if (_mitm) {

		BN_CTX *ctx = BN_CTX_new();

		// read in password dictionary file
		std::vector<std::string> passwords;
		char *relativePath = "/challenge-files/set5/password-list.txt";
		std::string filePath = executable_relative_path(relativePath);
		std::ifstream in(filePath);
		if (!in) {
			std::cout << "Cannot open password dictionary input file.\n";
			response.special = ERR;
			return response;
		}
		char line[255];
		int linecount = 0;
		while (in) {
			in.getline(line, 255);
			// read in each line, skip lines starting with '#'
			if (strlen(line) > 0 && line[0] != '#') {
				std::string theline = std::string(line);
				passwords.push_back(theline);
				linecount++;
			}
		}
		in.close();
		
		// generate HMAC for each password and test 
		ByteVector salt = ByteVector();
		BIGNUM *v = BN_new();
		BIGNUM *S = BN_new();
		BIGNUM *temp = BN_new();
		BIGNUM *temp2 = BN_new();
		bn_to_bytevector(_salt, &salt);
		for (size_t i = 0; i < passwords.size(); i++) {

			std::cout << "Testing password " << passwords[i] << std::endl;

			// compute x from PW and salt
			ByteVector pw = ByteVector((char *)passwords[i].c_str(), ASCII);
			ByteVector saltedPW = ByteVector();
			bv_concat(&salt, &pw, &saltedPW);
			ByteVector xH = ByteVector();
			ByteEncryption::sha256(&saltedPW, &xH);
			BIGNUM *x = bn_from_bytevector(&xH);

			// calculate v
			if (!BN_mod_exp(v, _g, x, _N, ctx)) {
				BN_free(x);
				BN_free(v);
				BN_free(S);
				BN_free(temp);
				BN_CTX_free(ctx);
				response.special = ERR;
				return response;
			}

			// compute S
			if (!BN_mod_exp(temp, v, _simple_u, _N, ctx)) {
				BN_free(x);
				BN_free(v);
				BN_free(S);
				BN_free(temp);
				BN_CTX_free(ctx);
				response.special = ERR;
				return response;
			}
			if (!BN_mod_mul(temp, _A, temp, _N, ctx)) {
				BN_free(x);
				BN_free(v);
				BN_free(temp);
				BN_CTX_free(ctx);
				response.special = ERR;
				return response;
			}
			if (!BN_mod_exp(S, temp, _b, _N, ctx)) {
				BN_free(x);
				BN_free(v);
				BN_free(S);
				BN_free(temp);
				BN_CTX_free(ctx);
				response.special = ERR;
				return response;
			}

			// compute K
			ByteVector SBV = ByteVector();
			bn_to_bytevector(S, &SBV);
			ByteVector K = ByteVector();
			ByteEncryption::sha256(&SBV, &K);

			// compute HMAC(K,SALT)
			ByteVector hmac = ByteVector();
			ByteEncryption::sha256_HMAC(&salt, &K, &hmac);
			if (hmac.equal(&input.data)) {
				std::cout << "MITM server found password match: " << passwords[i] << std::endl;
				BN_free(x);
				BN_free(v);
				BN_free(S);
				BN_free(temp);
				BN_CTX_free(ctx);
				response.special = OK;
				return response;
			}

			BN_free(x);
		}

		BN_free(v);
		BN_free(S);
		BN_free(temp);
		BN_CTX_free(ctx);
		std::cout << "MITM server did not find a password match" << std::endl;
		response.special = NOTOK;
		return response;
	}

	// generate K = SHA256(_S)
	ByteVector S = ByteVector();
	bn_to_bytevector(_S, &S);
	ByteVector K = ByteVector();
	ByteEncryption::sha256(&S, &K);

	// generate HMAC-SHA265(K, salt)
	ByteVector salt = ByteVector();
	bn_to_bytevector(_salt, &salt);
	ByteVector hmac = ByteVector();
	ByteEncryption::sha256_HMAC(&salt, &K, &hmac);

	// test input provided by client
	if (!hmac.equal(&input.data)) {
		response.special = NOTOK;
	}
	else {
		response.special = OK;
	}

	_state = 0;

	return response;
}