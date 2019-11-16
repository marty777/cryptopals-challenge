#pragma once
#include "openssl\bn.h"
#include "ByteVector.h"

// exchanged by client and server. Passes 0, 1 or 2 data objects as concatenated raw binary.
enum srp_message_special { RESET, EXCHANGE_KEYS, HMAC_VERIFY, OK, NOTOK, ERR };
struct SRP_message {
	ByteVector data;
	size_t first_item_len;
	int num_items;
	srp_message_special special; // RESET = reset connection (client). EXCHANGE_KEYS = first exchange (set for client and server messages), HMAC_VERIFY = second exchange (set for client and server messages), OK = OK (server), NOTOK = NOT OK (server), ERR = Error (server)
};

class SRPServer
{
public:

	bool init_err;

	SRPServer(BIGNUM *N, BIGNUM *g, BIGNUM *k, char *email, char *password);
	~SRPServer();
	SRP_message response(SRP_message input);


private:
	BN_CTX *_ctx;
	BIGNUM *_N;
	BIGNUM *_g;
	BIGNUM *_k;
	ByteVector _I;
	ByteVector _P;
	BIGNUM *_salt;
	BIGNUM *_v;
	BIGNUM *_A;
	BIGNUM *_b;
	BIGNUM *_B;
	BIGNUM *_S;
	int _state; // 0 = awaiting username, client public key, 1 = awaiting HMAC.

	SRP_message key_exchange(SRP_message input);
	SRP_message hmac_validation(SRP_message input);
};