#include "SRPServer.h"
#include "BNUtility.h"
#include "Utility.h"
#include <iostream>


SRPServer::SRPServer(ByteVector N, int g, int k, char *email, char *password) {
	_ctx = BN_CTX_new();
	_N = bn_from_bytevector(&N);
	_g = bn_from_word(g);
	_k = bn_from_word(k);
	_I = ByteVector(email, ASCII);
	_P = ByteVector(password, ASCII);
	_salt = BN_new();
	if (!BN_rand(_salt, 64, -1, 0)) { // random 64 bit integer
		std::cerr << "Error initializing salt in SRP_Server" << std::endl;
	}
	// generate sha256 hash of salt + password
	ByteVector pwBV = ByteVector(password, ASCII);
	ByteVector saltBV = ByteVector();
	bn_to_bytevector(_salt, &saltBV);
	ByteVector saltedPW = ByteVector(saltBV.length() + pwBV.length());
	saltBV.copyBytesByIndex(&saltedPW, 0, saltBV.length(), 0);
	pwBV.copyBytesByIndex(&saltedPW, 0, pwBV.length(), saltBV.length());

	// convert pw hash to BN integer
	BIGNUM *x = bn_from_bytevector(&saltedPW);

	// v = g ^ x % N
	_v = BN_new();
	if (!BN_mod_exp(_v, _g, x, _N, _ctx)) {
		std::cerr << "Error computing v in SRP_Server" << std::endl;
		BN_free(x);
		return;
	}

	_state = 0;
	_b = BN_new();
	BN_rand_range(_b, _N);
	_A = NULL;

	BN_free(x);
}


SRPServer::~SRPServer() {
	BN_CTX_free(_ctx);
	BN_free(_N);
	BN_free(_g);
	BN_free(_k);
	BN_free(_salt);
	BN_free(_v);
	BN_free(_b);
	if (_A != NULL) {
		BN_free(_A);
	}
}

SRP_message SRPServer::response(SRP_message input) {
	SRP_message response;
	response.num_items = 0;
	response.first_item_len = 0;
	response.data = ByteVector();

	ByteVector I = ByteVector();
	ByteVector A = ByteVector();
	ByteVector HMAC = ByteVector();

	BIGNUM *B;
	BIGNUM *kv;
	ByteVector saltBV = ByteVector();
	ByteVector BBV = ByteVector();

	if (input.special == -1) {
		_state = 0;
		response.num_items = 0;
		response.special = OK;
		return response;
	}
	switch (_state) {
	case 0: // waiting for client email and public key
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

		if (!I.equal(&_I)) {
			response.special = NOTOK;
			return response;
		}

		_A = bn_from_bytevector(&A);

		// compute B
		B = BN_new();
		kv = BN_new();
		// B = k * v + g ^ b % N
		if (!BN_mul(kv, _k, _v, _ctx)) {
			response.special = ERR;
			return response;
		}
		if (!BN_mod_exp(B, _g, _b, _N, _ctx)) {
			response.special = ERR;
			return response;
		}
		if (!BN_add(B, kv, B)) {
			response.special = ERR;
			return response;
		}

		bn_to_bytevector(_salt, &saltBV);
		bn_to_bytevector(B, &BBV);
		bv_concat(&saltBV, &BBV, &response.data);
		response.num_items = 2;
		response.first_item_len = saltBV.length();

		BN_free(B);
		BN_free(kv);
		return response;
		break;
	case 1: // waiting for client HMAC
		break;
	default:
		break;
	}
}
