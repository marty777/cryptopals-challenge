#include "Set6.h"
#include <iostream>
#include <vector>
#include <fstream>
#include "ByteVector.h"
#include "ByteEncryption.h"
#include "openssl\bn.h"
#include "BNUtility.h"
#include "Utility.h"

#include "RSAClient.h"
#include "DSAClient.h"

using namespace std;

void Set6Challenge41() {
	vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	// create new client to represent oracle
	cout << "Creating oracle..." << endl;
	RSAClient client = RSAClient(1024);

	BIGNUM *E = BN_new();
	BIGNUM *N = BN_new();
	bn_add_to_ptrs(E, &bn_ptrs);
	bn_add_to_ptrs(N, &bn_ptrs);
	client.public_key(E, N);

	ByteVector secretmessage = ByteVector("This is a secret!", ASCII);
	ByteVector encrypted1 = ByteVector();

	// obtain unpadded ciphertext
	cout << "Creating initial ciphertext C..." << endl;
	client.encrypt_bv(&secretmessage, &encrypted1);
	BIGNUM *ciphertext = bn_from_bytevector(&encrypted1, &bn_ptrs);
	
	// S = random number mod N != 1
	cout << "Generating random S..." << endl;
	BIGNUM *S = BN_new();
	bn_add_to_ptrs(S, &bn_ptrs);
	if (!BN_rand_range(S, N)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	// if S = 1 -> S = 2
	if (BN_cmp(S, BN_value_one()) == 0) {
		if (!BN_add(S, S, BN_value_one())) {
			cout << "BN error" << endl;
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return;
		}
	}

	// set C2 = ((S**E mod N) C) mod N
	cout << "Creating second ciphertext C'..." << endl;
	BIGNUM * ciphertext2 = BN_new();
	bn_add_to_ptrs(ciphertext2, &bn_ptrs);

	if (!BN_mod_exp(ciphertext2, S, E, N, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mod_mul(ciphertext2, ciphertext2, ciphertext, N, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}

	// confirm C' != C (for the purposes of our oracle that won't decrypt the same message twice)
	if (BN_cmp(ciphertext, ciphertext2) == 0) {
		cout << "C and C' are equal" << endl;
	}
	else {
		cout << "C and C' are not equal" << endl;
	}

	// obtain decryption of C2
	cout << "Decrypting C'..." << endl;
	ByteVector c2 = ByteVector();
	ByteVector p2 = ByteVector();
	bn_to_bytevector(ciphertext2, &c2);
	client.decrypt_bv(&c2, &p2);

	// determine actual plaintext
	cout << "Obtaining original plaintext..." << endl;
	BIGNUM *plaintext2 = bn_from_bytevector(&p2, &bn_ptrs);
	BIGNUM *s_inverse = BN_new();
	bn_add_to_ptrs(s_inverse, &bn_ptrs);
	if (!BN_mod_inverse(s_inverse, S, N, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	BIGNUM *plaintext = BN_new();
	bn_add_to_ptrs(plaintext, &bn_ptrs);
	if (!BN_mod_mul(plaintext, plaintext2, s_inverse, N, ctx)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	ByteVector result = ByteVector();
	bn_to_bytevector(plaintext, &result);
	cout << "Result: " << endl << result.toStr(ASCII) << endl;

	
	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
}

void Set6Challenge42() {

	vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	cout << "Testing RSA block padding..." << endl;
	RSAClient client1 = RSAClient(1024);
	ByteVector bv = ByteVector("The length of the data D shall not be more than k-11 octets, which is positive since the length k of the modulus is at least 12 octets. This limitation guarantees that the length of the padding string PS is at least eight octets, which is a security condition.", ASCII);
	ByteVector encrypted = ByteVector();
	ByteVector decrypted = ByteVector();

	cout << "Encrypting multiblock message..." << endl;
	client1.encrypt_bv(&bv, &encrypted, true, 1);
	cout << "Decrypting multiblock message..." << endl;
	client1.decrypt_bv(&encrypted, &decrypted, true, 1);
	cout << "Result " << (bv.equal(&decrypted) ? " (matches original):" : " (does not match original):") << endl << decrypted.toStr(ASCII) << endl;

	cout << "Testing MD4 RSA signing of data..." << endl;
	ByteVector signature = ByteVector();
	client1.sign_bv(&bv, &signature);
	if (client1.verify_signature_bv(&signature, &bv)) {
		cout << "Public key of signature validates digest" << endl;
	}
	else {
		cout << "Public key of signature does not validate digest" << endl;
	}

	cout << "Forging signature..." << endl;
	ByteVector himom = ByteVector("hi mom", ASCII);
	ByteVector hash = ByteVector();
	ByteEncryption::md4(&himom, &hash);
	ByteVector data = ByteVector(hash.length() + 5);
	data[0] = 0x00;
	data[1] = 0x01;
	data[2] = 0xff;
	data[3] = 0x00; // end of padding
	data[4] = 0x02; // digest specification field in our signature format indicating MD4
	hash.copyBytesByIndex(&data, 0, hash.length(), 5);

	BIGNUM *data_bn = bn_from_bytevector(&data, &bn_ptrs);
	BIGNUM *three = bn_from_word(3, &bn_ptrs);
	BIGNUM *cube_root_N = BN_new();
	bn_add_to_ptrs(cube_root_N, &bn_ptrs);
	

	BIGNUM *clientE = BN_new();
	BIGNUM *clientN = BN_new();
	bn_add_to_ptrs(clientE, &bn_ptrs);
	bn_add_to_ptrs(clientN, &bn_ptrs);
	client1.public_key(clientE, clientN);

	bn_nth_root(clientN, three, cube_root_N);
	
	// right-pad forged signature with zeroes to proper length for a block less 1.
	// The less 1 is because of the initial zero byte in our padding. For it to 
	// be re-appended after cubing, the result needs to be one byte short
	int N_bytes = BN_num_bytes(clientN);
	int data_bytes = BN_num_bytes(data_bn);
	if (N_bytes <= data_bytes) { // we've picked a bad key size or something in the setup
		cout << "Something's wrong" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	// data_bn should be one byte shorter than N
	if (!BN_lshift(data_bn, data_bn, (N_bytes - data_bytes - 1)*8)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}

	BIGNUM *cuberoot = BN_new();
	bn_add_to_ptrs(cuberoot, &bn_ptrs);
	if (!bn_nth_root(data_bn, three, cuberoot)) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_add(cuberoot, cuberoot, BN_value_one())) {
		cout << "BN error" << endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return;
	}
	
	// we could check this result and maybe tweak it slightly if it's off, but let's live dangerously.

	ByteVector forgedsig = ByteVector();
	bn_to_bytevector(cuberoot, &forgedsig);

	if (client1.verify_signature_bv(&forgedsig, &himom)) {
		cout << "Forged valid signature for string '" << himom.toStr(ASCII) << "'" << endl;
	}
	else {
		cout << "Did not forge valid signature for string '" << himom.toStr(ASCII) << "'" << endl;
	}

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
}

void Set6Challenge43() {

	vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	DSAClient client = DSAClient();
	int userID = 1;
	client.generateUserKey(userID);
	
	// could have used a note in the challenge instructions that the string matching the provided SHA1 hash has a LF character at the end. That took a while to seach for.
	ByteVector data = ByteVector("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n", ASCII);
	ByteVector expectedHash = ByteVector("d2d0714f014a9784047eaeccf956520045c45265", HEX);
	ByteVector verifyHash = ByteVector();
	ByteEncryption::sha1(&data, &verifyHash);
	if (!expectedHash.equal(&verifyHash)) {
		cout << "Expected hash of input string does not match" << endl;
		return;
	}
	
	DSASignature sig;
	sig.r = NULL;
	sig.s = NULL;
	cout << "Generating test signature..." << endl;
	if (!client.generateSignature(&data, &sig, userID)) {
		cout << "Issue generating signature" << endl;
		return;
	}

	cout << "Verifying test signature..." << endl;
	if (client.verifySignature(&data, &sig, userID)) {
		cout << "Signature verified" << endl;
	}
	else {
		cout << "Signature did not verify" << endl;
	}

	
	// test out recovering x with known k with several trials
	cout << "Testing recovery of x with known k..." << endl;
	BIGNUM *q = client.getQ();
	bn_add_to_ptrs(q, &bn_ptrs);

	int successes = 0;
	for (int i = 2; i < 12; i++) {
		vector<BIGNUM *> bn_ptrs2;
		client.generateUserKey(i);
		ByteVector testdata = ByteVector(256);
		testdata.random();
		ByteVector testhash = ByteVector();
		ByteEncryption::sha1(&testdata, &testhash);
		BIGNUM *testhash_bn = bn_from_bytevector(&testhash, &bn_ptrs2);
		BIGNUM *testk = BN_new();
		bn_add_to_ptrs(testk, &bn_ptrs2);
		client.generateSignature(&testdata, &sig, i, testk);
		BIGNUM *actualx = client.getX(i);
		BIGNUM * testx = DSA_xfromk(&sig, &testdata, testk, q);
		if (testx != NULL) {
			if (BN_cmp(testx, actualx) == 0) {
				successes++;
			}
			else {
				cout << "Trial " << i << " failed " << endl << BN_bn2dec(testx) << endl << BN_bn2dec(actualx) << endl;
			}
		}
		else {
			cout << i << ": DSA_xfromk returned NULL" << endl;
			bn_free_ptrs(&bn_ptrs2);
			break;
		}
		bn_free_ptrs(&bn_ptrs2);
	}
	if (successes == 10) {
		cout << "All tests successful" << endl;
	}
	else {
		cout << successes << " out of 10 tests successful" << endl;
	}

	

	// Now try out the provided signature
	cout << "Trialing restricted k to determine private key corresponding to provided public key and signature (this may take some time)..." << endl;
	ByteVector verificationHash = ByteVector("0954edd5e0afe5542a4adf012611a91912a3ec16", HEX);
	DSAClient finalclient = DSAClient(true); 
	BIGNUM *final_y = BN_new();
	BN_hex2bn(&final_y, "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17");
	BIGNUM *final_q = finalclient.getQ();
	BIGNUM *final_p = finalclient.getP();
	BIGNUM *final_g = finalclient.getG();
	BIGNUM *final_k = bn_from_word(0, &bn_ptrs);
	BIGNUM *two_16 = bn_from_word(65536, &bn_ptrs); // 2^16
	// provided s and r (presumably in decimal rather than hex)
	BN_dec2bn(&sig.r, "548099063082341131477253921760299949438196259240");
	BN_dec2bn(&sig.s, "857042759984254168557880549501802188789837994940");

	BIGNUM *test_y = BN_new();
	bn_add_to_ptrs(final_q, &bn_ptrs);
	bn_add_to_ptrs(final_p, &bn_ptrs);
	bn_add_to_ptrs(final_g, &bn_ptrs);
	bn_add_to_ptrs(final_y, &bn_ptrs);
	bn_add_to_ptrs(test_y, &bn_ptrs);
	bool found = false;
	while (BN_cmp(final_k, two_16) <= 0) {
		BIGNUM * testx = DSA_xfromk(&sig, &data, final_k, final_q);
		if (testx == NULL) {
			cout << "DSA_xfromk returned NULL on final_k " << BN_bn2dec(final_k) << endl;
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return;
		}

		// given s,r, the hash, and our presumed k
		// determine x and see if it corresponds to the provided public key y
		if (!BN_mod_exp(test_y, final_g, testx, final_p, ctx)) {
			cout << "Issue generating test y for k = " << BN_bn2dec(final_k) << endl;
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return;
		}

		if (BN_cmp(test_y, final_y) == 0) {
			found = true;
			break;
		}

		BN_free(testx);
		if (!BN_add(final_k, final_k, BN_value_one())) {
			cout << "Issue incrementing final k" << endl;
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return;
		}
	}


	if (!found) {
		cout << "No match found" << endl;
	}
	else {
		cout << "Matching k found " << BN_bn2dec(final_k) << endl;
		BIGNUM *final_x = DSA_xfromk(&sig, &data, final_k, final_q);
		bn_add_to_ptrs(final_x, &bn_ptrs);
		
		BIGNUM *testy = BN_new();
		bn_add_to_ptrs(testy, &bn_ptrs);
		BN_mod_exp(test_y, final_g, final_x, final_p, ctx);
		
		// compute r and s to confirm
		ByteVector hash = ByteVector();
		ByteEncryption::sha1(&data, &hash);
		BIGNUM *hash_bn = bn_from_bytevector(&hash, &bn_ptrs);
		BIGNUM *final_r = BN_new();
		BIGNUM *final_s = BN_new();
		bn_add_to_ptrs(final_r, &bn_ptrs);
		bn_add_to_ptrs(final_s, &bn_ptrs);

		if (!BN_mod_exp(final_r, final_g, final_k, final_p, ctx)) {
			cout << "Error generating r" << endl;
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return;
		}
		if (!BN_mod(final_r, final_r, final_q, ctx)) {
			cout << "Error generating r" << endl;
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return;
		}
		if (BN_cmp(sig.r, final_r) != 0) {
			cout << "Derived r does not match provided" << endl;
			cout << BN_bn2dec(sig.r) << endl << BN_bn2dec(final_r) << endl;
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return;
		}

		BIGNUM *final_k_inverse = BN_new();
		bn_add_to_ptrs(final_k_inverse, &bn_ptrs);
		if (!BN_mod_inverse(final_k_inverse, final_k, final_q, ctx)) {
			cout << "Error generating inverse of k" << endl;
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return;
		}
		if (!BN_mod_mul(final_s, final_x, final_r, final_q, ctx)) {
			cout << "Error generating s" << endl;
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return;
		}
		if (!BN_mod_add(final_s, hash_bn, final_s, final_q, ctx)) {
			cout << "Error generating s" << endl;
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return;
		}
		if (!BN_mod_mul(final_s, final_k_inverse, final_s, final_q, ctx)) {
			cout << "Error generating s" << endl;
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return;
		}
		if (BN_cmp(sig.s, final_s) != 0) {
			cout << "Derived s does not match provided" << endl;
			cout << BN_bn2dec(sig.r) << endl << BN_bn2dec(final_r) << endl;
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return;
		}

		cout << "Private key that generates identical signature found: " << BN_bn2hex(final_x) << endl;
		// the confirmation hash is the SHA-1 hash of the hex string (lowercase -> important) of x
		ByteVector final_x_bv = ByteVector();
		bn_to_bytevector(final_x, &final_x_bv);
		ByteVector hexString = ByteVector(final_x_bv.toStr(HEX), ASCII);
		ByteVector final_x_hash = ByteVector();
		ByteEncryption::sha1(&hexString, &final_x_hash);
		cout << "Private key has SHA-1 hash " << final_x_hash.toStr(HEX) << endl;
		if (final_x_hash.equal(&verificationHash)) {
			cout << "Hash of private key matches provided verification hash "  << verificationHash.toStr(HEX) << endl;
		}
		else {
			cout << "Hash of private key does not match provided verification hash " << verificationHash.toStr(HEX) << endl;
		}
		
	}

	BN_free(sig.r);
	BN_free(sig.s);

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
}

void Set6Challenge44() {
	// deriving the equation used to determine re-used k:
	// with fixed k, r will be constant
	// s1 = k^-1 (H(m1) + xr) % q
	// s2 = k^-1 (H(m2) + xr) % q
	// (s1 - s2) % q = (k^-1 (H(m1) + xr)) - (k^-1(H(m2) + xr)) % q
	// (s1 - s1) % q = (k^-1) * (H(m1) - H(m2) + xr - xr) % q
	// rearranged gives
	// k % q = k (k <= q-1) = (H(m1) - H(m2)) / (s1 - s2) % q

	vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *y = BN_new();
	bn_add_to_ptrs(y, &bn_ptrs);
	if (!bn_handle_error(
		BN_hex2bn(&y, "2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821"),
		"Error parsing y", &bn_ptrs, ctx)) {
		return;
	}

	std::vector<std::string> lines;
	char *relativePath = "/challenge-files/set6/44.txt";
	std::string filePath = executable_relative_path(relativePath);
	std::ifstream in(filePath);
	if (!in) {
		std::cout << "Cannot open input file.\n";
		return;
	}
	char line[255];
	int linecount = 0;
	while (in) {
		in.getline(line, 255);
		// read in each line, skip lines starting with '#'
		if (strlen(line) > 0 && line[0] != '#') {
			std::string theline = std::string(line);
			lines.push_back(theline);
			linecount++;
		}
	}
	in.close();

	std::vector<ByteVector> msg_r;
	std::vector<BIGNUM *> s_r;
	std::vector<BIGNUM *> r_r;
	std::vector<BIGNUM *> m_r;
	for (size_t i = 0; i < lines.size(); i++) {
		if (i % 4 == 0) {
			string substr = lines[i].substr(strlen("msg: "), lines[i].length() - strlen("msg: "));
			ByteVector msg = ByteVector((char *)substr.c_str(), ASCII);
			ByteVector hash = ByteVector();
			ByteEncryption::sha1(&msg, &hash);
			BIGNUM *m = bn_from_bytevector(&hash, &bn_ptrs);
			msg_r.push_back(msg);
			m_r.push_back(m);
		}
		else if (i % 4 == 1) {
			string substr = lines[i].substr(strlen("s: "), lines[i].length() - strlen("s: "));
			BIGNUM *s = BN_new();
			bn_add_to_ptrs(s, &bn_ptrs);
			if (!bn_handle_error(BN_dec2bn(&s, substr.c_str()), "Error adding s", &bn_ptrs, ctx)) {
				return;
			}
			s_r.push_back(s);
		}
		else if(i % 4 == 2) {
			string substr = lines[i].substr(strlen("r: "), lines[i].length() - strlen("r: "));
			BIGNUM *r = BN_new();
			bn_add_to_ptrs(r, &bn_ptrs);
			if (!bn_handle_error(BN_dec2bn(&r, substr.c_str()), "Error adding r", &bn_ptrs, ctx)) {
				return;
			}
			r_r.push_back(r);
		}
		// ignore the provided hashes. I'm calculating them myself
	}

	// just using this to retrieve the default parameters
	DSAClient client = DSAClient(true); 

	BIGNUM *g = client.getG();
	BIGNUM *p = client.getP();
	BIGNUM *q = client.getQ();

	// for each pair of messages, assume a re-used k. Attempt to calulate k, 
	// derive the corresponding x and use it to compute y. If y matches our 
	// known y, we've found the re-used nonce and the actual x.
	// Alternately, we can compute an x from k using each message's signature
	// and see if those match.

	BIGNUM *k = BN_new();
	BIGNUM *x = BN_new();
	BIGNUM *x2 = BN_new();
	BIGNUM *test_y = BN_new();
	BIGNUM *temp = BN_new();
	bn_add_to_ptrs(k, &bn_ptrs);
	bn_add_to_ptrs(x, &bn_ptrs);
	bn_add_to_ptrs(x2, &bn_ptrs);
	bn_add_to_ptrs(test_y, &bn_ptrs);
	bn_add_to_ptrs(temp, &bn_ptrs);
	bool found = false;
	for (size_t i = 0; i < msg_r.size(); i++) {
		if (found) {
			break;
		}
		for (size_t j = 0; j < msg_r.size(); j++) {
			
			if (j == i) {
				continue;
			}

			// with a constant g, p and q, r will be identical between two messages with the same k ( r= (g^k %p)) % q
			if (!BN_cmp(r_r[i], r_r[j]) == 0) {
				continue;
			}
		
			BIGNUM *m1 = m_r[i];
			BIGNUM *m2 = m_r[j];
			BIGNUM *s1 = s_r[i];
			BIGNUM *s2 = s_r[j];

			// calculate k assuming a re-used k
			if (!bn_handle_error(BN_mod_sub(k, m1, m2, q, ctx), "Error calculating k", &bn_ptrs, ctx)) {
				return;
			}
			if (!bn_handle_error(BN_mod_sub(temp, s1, s2, q, ctx), "Error calculating k", &bn_ptrs, ctx)) {
				return;
			}
			
			if (BN_mod_inverse(temp, temp, q, ctx) == NULL) {
				cout << "Error calculating k" << endl;
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return;
			}
			if (!bn_handle_error(BN_mod_mul(k, k, temp, q, ctx), "Error calculating k", &bn_ptrs, ctx)) {
				return;
			}

			// calculate x from k (using s and r from signature i)
			if (BN_mod_inverse(temp, r_r[i], q, ctx) == NULL) {
				cout << "Error calculating x" << endl;
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return;
			}
			if (!bn_handle_error(BN_mod_mul(x, s_r[i], k, q, ctx), "Error calculating x", &bn_ptrs, ctx)) {
				return;
			}
			if (!bn_handle_error(BN_mod_sub(x, x, m_r[i], q, ctx), "Error calculating x", &bn_ptrs, ctx)) {
				return;
			}
			if (!bn_handle_error(BN_mod_mul(x, x, temp, q, ctx), "Error calculating x", &bn_ptrs, ctx)) {
				return;
			}

			// calculate y
			if (!bn_handle_error(BN_mod_exp(test_y, g, x, p, ctx), "Error calculating test y", &bn_ptrs, ctx)) {
				return;
			}

			if (BN_cmp(test_y, y) == 0) {
				cout << "Match found between signatures " << i << " and " << j << endl;
				cout << "Derived private key: " << BN_bn2hex(x) << endl;
				found = true;
				break;
			}
		}
	}
	if (!found) {
		cout << "No match found" << endl;
	}
	else {
		ByteVector verificationHash = ByteVector("ca8f6f7c66fa362d40760d135b763eb8527d3d52", HEX);
		ByteVector testHash = ByteVector();
		ByteVector x_bv = ByteVector();
		bn_to_bytevector(x, &x_bv);
		ByteVector x_hex = ByteVector(x_bv.toStr(HEX), ASCII);
		ByteEncryption::sha1(&x_hex, &testHash);
		if (testHash.equal(&verificationHash)) {
			cout << "Calculated private key matches verification hash" << endl;
		}
		else {
			cout << "Calculated private key does not match verification hash" << endl;
		}
	}

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
}

void Set6Challenge45() {

	vector<BIGNUM *> bn_ptrs;
	BN_CTX *ctx = BN_CTX_new();

	// setup p+1
	BIGNUM *p_plus_one = BN_new();
	bn_add_to_ptrs(p_plus_one, &bn_ptrs);
	if (!bn_handle_error(BN_hex2bn(&p_plus_one, "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1")
		, "Error creating p+1", &bn_ptrs, ctx)) {
		return;
	}
	if (!bn_handle_error(BN_add(p_plus_one, p_plus_one, BN_value_one()), "Error creating p+1", &bn_ptrs, ctx)) {
		return;
	}

	// client with g parameter 0
	DSAClient client_0 = DSAClient(true, "0"); 

	// client with g parameter p+1
	DSAClient client_p_plus_one = DSAClient(true, BN_bn2hex(p_plus_one));

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);

}


int Set6() {
	cout << "### SET 6 ###" << endl;
	cout << "Set 6 Challenge 41" << endl;
	Set6Challenge41();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 6 Challenge 42" << endl;
	Set6Challenge42();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 6 Challenge 43" << endl;
	Set6Challenge43();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 6 Challenge 44" << endl;
	Set6Challenge44();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	cout << "Set 6 Challenge 45" << endl;
	Set6Challenge45();
	// Pause before continuing
	cout << "Press enter to continue..." << endl;
	getchar();
	return 0;
}