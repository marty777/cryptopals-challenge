#include "RSAClient.h"
#include "ByteEncryption.h"
#include "BNUtility.h"
#include "Utility.h"
#include <iostream>
#include <assert.h>

RSAClient::RSAClient(int bits, bool verbose)
{
	init_err = false;
	// might want to add a proper way to seed the RNG
	// generate p and q
	p = BN_new();
	q = BN_new();
	if (p == NULL || q == NULL) {
		init_err = true;
		return;
	}
	if (verbose) {
		std::cout << "Generating P..." << std::endl;
	}
	BN_generate_prime_ex(p, bits/2, 0, NULL, NULL, NULL);
	if (verbose) {
		std::cout << "Generating Q..." << std::endl;
	}
	BN_generate_prime_ex(q, bits/2, 0, NULL, NULL, NULL);
	if (verbose) {
		std::cout << "Computing N..." << std::endl;
	}
	// compute n
	BN_CTX *ctx = BN_CTX_new();
	if (ctx == NULL) {
		init_err = true;
		return;
	}
	n = BN_new();
	if (n == NULL) {
		init_err = true;
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mul(n, p, q, ctx)) {
		init_err = true;
		BN_CTX_free(ctx);
		return;
	}

	if (verbose) {
		std::cout << "n = " << BN_bn2dec(n) << std::endl;
	}

	e = BN_new();
	if (e == NULL) {
		init_err = true;
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_set_word(e, 3)) {
		init_err = true;
		BN_CTX_free(ctx);
		return;
	}

	d = BN_new();
	if (d == NULL) {
		init_err = true;
		BN_CTX_free(ctx);
		return;
	}

	BIGNUM *p_1 = BN_new();
	BIGNUM *q_1 = BN_new();
	BIGNUM *et = BN_new();
	if (p_1 == NULL || q_1 == NULL || et == NULL) {
		init_err = true;
		if (p_1 != NULL) {
			BN_free(p_1);
		}
		if (q_1 != NULL) {
			BN_free(q_1);
		}
		if (et != NULL) {
			BN_free(et);
		}
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_sub(p_1, p, BN_value_one())) {
		init_err = true;
		BN_free(p_1);
		BN_free(q_1);
		BN_free(et);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_sub(q_1, q, BN_value_one())) {
		init_err = true;
		BN_free(p_1);
		BN_free(q_1);
		BN_free(et);
		BN_CTX_free(ctx);
		return;
	}
	if (!BN_mul(et, p_1, q_1, ctx)) {
		init_err = true;
		BN_free(p_1);
		BN_free(q_1);
		BN_free(et);
		BN_CTX_free(ctx);
		return;
	}
	// done with p_1, q_1
	BN_free(p_1);
	BN_free(q_1);

	// d invmod(e, et)
	if (!bn_invmod(e, et, d)) {
		init_err = true;
		BN_free(et);
		BN_CTX_free(ctx);
		return;
	}

	if (verbose) {
		std::cout << "d = " << BN_bn2dec(d) << std::endl;
	}

	// done with et
	BN_free(et);

	if (verbose) {
		std::cout << "Initialization complete." << std::endl;
	}

	BN_CTX_free(ctx);
}

// returns false on BIGNUM error
bool RSAClient::encrypt_bv(ByteVector *input, ByteVector *encrypted, bool padded, int padtype) {
	BN_CTX *ctx = BN_CTX_new();
	std::vector<BIGNUM *> bn_ptrs;
	BIGNUM *out = BN_new();
	bn_add_to_ptrs(out, &bn_ptrs);

	if (padded) {

		int blocksize = BN_num_bytes(n);
		assert(blocksize >= 12);
		int datablock_size = blocksize - 11;
		int blocknum = input->length() / datablock_size;
		if (input->length() % datablock_size != 0) {
			blocknum++;
		}
		ByteVector inblock = ByteVector(blocksize);
		ByteVector outblock = ByteVector(blocksize);
		encrypted->resize(blocksize * blocknum);
		for (size_t i = 0; i < input->length(); i += datablock_size) {
			size_t thislen = (input->length() - i < datablock_size ? input->length() - i : datablock_size);
			size_t padlen = blocksize - thislen - 3;
			inblock.allBytes(0);
			inblock[0] = 0x00;
			inblock[1] = (byte) (0xff & padtype);
			for (size_t j = 2; j < padlen + 2; j++) {
				if (padtype == 1) {
					inblock[j] = 0xff;
				}
				else if (padtype == 2) {
					inblock[j] = (byte) rand_range(1, 255);
				}
				else {
					inblock[j] = 0x00;
				}
			}
			inblock[2 + padlen] = 0x00;
			
			input->copyBytesByIndex(&inblock, i, thislen, 3 + padlen);
			
			BIGNUM *in = bn_from_bytevector(&inblock, &bn_ptrs);

			if (!BN_mod_exp(out, in, e, n, ctx)) {
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return false;
			}

			bn_to_bytevector(out, &outblock);
			
			/*ByteVector decrypt_test = ByteVector();
			BIGNUM *test = BN_new();
			bn_add_to_ptrs(test, &bn_ptrs);
			if (!BN_mod_exp(test, out, d, n, ctx)) {
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return false;
			}
			bn_to_bytevector(test, &decrypt_test);
			decrypt_test.printHexStrByBlocks(16);*/

			if (outblock.length() < blocksize) {
				outblock.copyBytesByIndex(encrypted, 0, outblock.length(), i*blocksize);
				for (size_t j = outblock.length(); j < blocksize; j++) {
					(*encrypted)[i*blocksize + j] = 0x00;
				}
			}
			else {
				outblock.copyBytesByIndex(encrypted, 0, outblock.length(), (i/datablock_size)*blocksize);
			}
		}
	}
	else {
		BIGNUM *in = bn_from_bytevector(input, &bn_ptrs);

		if (!BN_mod_exp(out, in, e, n, ctx)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}

		bn_to_bytevector(out, encrypted);
	}

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
	return true;
}
// returns false on BIGNUM error
bool RSAClient::decrypt_bv(ByteVector *encrypted, ByteVector *output, bool padded, int padtype) {
	BN_CTX *ctx = BN_CTX_new();
	std::vector<BIGNUM *> bn_ptrs;
	BIGNUM *out = BN_new();
	bn_add_to_ptrs(out, &bn_ptrs);

	if (padded) {
		int blocksize = BN_num_bytes(n);
		assert(blocksize >= 12);
		int datablock_size = blocksize - 11;
		int blocknum = encrypted->length() / blocksize;
		
		ByteVector inblock = ByteVector(blocksize);
		ByteVector outblock = ByteVector(blocksize);
		output->resize(datablock_size * blocknum);

		size_t datatotal = 0; // actual byte count for cases where datablock_size and data are not aligned
		for (size_t i = 0; i < encrypted->length(); i += blocksize) {
			encrypted->copyBytesByIndex(&inblock, i, blocksize, 0);
			
			BIGNUM *in = bn_from_bytevector(&inblock, &bn_ptrs);
			if (!BN_mod_exp(out, in, d, n, ctx)) {
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return false;
			}

			bn_to_bytevector(out, &outblock);
			
			// if the output is less than blocksize bytes, left-pad with zeros
			if (outblock.length() < blocksize) {
				ByteVector temp = ByteVector(&outblock);
				outblock.resize(blocksize);
				outblock.allBytes(0);
				temp.copyBytesByIndex(&outblock, 0, temp.length(), blocksize - temp.length());
			} 

			if (outblock[0] != 0x00) {
				std::cerr << "bad byte 0 expected 0x00" << i+0 << std::endl;
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return false;
			}
			if (outblock[1] != 0x00 && outblock[1] != 0x01 && outblock[1] != 0x02) {
				std::cerr << "bad byte 1 unknown blocktype " << (int)outblock[1] << " " << i + 0 << std::endl;
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return false;
			}

			size_t dataindex = 2;
			while (dataindex < blocksize) {
				if (outblock[1] == 0x00) { // type 0, looking for first non-zero byte
					if (outblock[dataindex] != 0) {
						break;
					}
				}
				else if (outblock[1] == 0x01) { // type 1, looking for first non-0xff byte + 1
					if (outblock[dataindex] == 0x00) {
						dataindex++;
						break;
					}
					else if(outblock[dataindex] != 0xff){
						std::cerr << "bad byte padding byte for type 1 " << (int)outblock[dataindex] << " " << i + dataindex << std::endl;
						bn_free_ptrs(&bn_ptrs);
						BN_CTX_free(ctx);
						return false;
					}
				}
				else if (outblock[1] == 0x02) {
					if (outblock[dataindex] == 0x00) {
						dataindex++;
						break;
					}
				}
				dataindex++;
			}
			if (dataindex == blocksize) {
				std::cerr << "No data found in block " << " " << i + dataindex << std::endl;
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return false;
			}
			datatotal += (blocksize - dataindex);
			outblock.printHexStrByBlocks(16);
			outblock.copyBytesByIndex(output, dataindex, outblock.length() - dataindex, (i/blocksize)*datablock_size);
 		}
		// if the output isn't a multiple of datablock_size
		output->resize(datatotal);
	}
	else {

		BIGNUM *in = bn_from_bytevector(encrypted, &bn_ptrs);

		if (!BN_mod_exp(out, in, d, n, ctx)) {
			bn_free_ptrs(&bn_ptrs);
			BN_CTX_free(ctx);
			return false;
		}

		bn_to_bytevector(out, output);
	}

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
	return true;
}

// The following is not a correct implemenation of RFC 2313. I only have MD4 hashing available at the moment, and I'm not using BER encoding
// as specified. There are only two fields in the data, a single byte giving the hash algorithm and the remainder being the 16 bytes of the hash,
// so this should be possible to interpret unambiguously.
bool RSAClient::sign_bv(ByteVector *input, ByteVector *signature) {
	BN_CTX *ctx = BN_CTX_new();
	std::vector<BIGNUM *> bn_ptrs;

	// if our data field isn't large enough to store an md4 hash in a single block.
	int blocksize = BN_num_bytes(n);
	assert(blocksize >= 12);
	int datablock_size = blocksize - 11;
	assert(datablock_size >= 16 + 1); // 16 byte hash + 1 byte denoting MD4

	// generate hash of input vector. 
	ByteVector hash = ByteVector();
	ByteEncryption::md4(input, &hash);

	// fill out the block
	ByteVector data = ByteVector(1 + hash.length());
	data[0] = 0x02; // denotes MD4
	hash.copyBytesByIndex(&data, 0, hash.length(), 1);
	ByteVector inblock = ByteVector(blocksize);
	inblock[0] = 0x00;
	inblock[1] = 0x01;
	for (size_t i = 2; i < blocksize - data.length() - 1; i++) {
		inblock[i] = 0xff;
	}
	inblock[blocksize - data.length() - 1] = 0;
	data.copyBytesByIndex(&inblock, 0, data.length(), blocksize - data.length());
	
	// encrypt using private key
	BIGNUM *in = bn_from_bytevector(&inblock, &bn_ptrs);
	BIGNUM *out = BN_new();
	bn_add_to_ptrs(out, &bn_ptrs);
	if (!BN_mod_exp(out, in, d, n, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}
	
	bn_to_bytevector(out, signature);

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
	return true;
}

// check that signature hash matches data
bool RSAClient::verify_signature_bv(ByteVector *signature, ByteVector *data) {
	BN_CTX *ctx = BN_CTX_new();
	std::vector<BIGNUM *> bn_ptrs;

	// if our data field isn't large enough to store an md4 hash in a single block.
	int blocksize = BN_num_bytes(n);
	assert(blocksize >= 12);
	int datablock_size = blocksize - 11;
	assert(datablock_size >= 16 + 1); // 16 byte hash + 1 byte denoting MD4

	ByteVector hash = ByteVector();
	ByteEncryption::md4(data, &hash);

	BIGNUM *in = bn_from_bytevector(signature, &bn_ptrs);
	BIGNUM *out = BN_new();
	bn_add_to_ptrs(out, &bn_ptrs);
	if (!BN_mod_exp(out, in, e, n, ctx)) {
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	ByteVector sigblock = ByteVector();
	bn_to_bytevector(out, &sigblock);

	// if the output is less than blocksize bytes, left-pad with zeros
	if (sigblock.length() < blocksize) {
		ByteVector temp = ByteVector(&sigblock);
		sigblock.resize(blocksize);
		sigblock.allBytes(0);
		temp.copyBytesByIndex(&sigblock, 0, temp.length(), blocksize - temp.length());
	}

	if (sigblock[0] != 0x00) {
		std::cerr << "bad byte 0 expected 0x00" << std::endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}
	if (sigblock[1] != 0x00 && sigblock[1] != 0x01 && sigblock[1] != 0x02) {
		std::cerr << "bad byte 1 unknown blocktype " << (int)sigblock[1] << std::endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	size_t dataindex = 2;
	while (dataindex < blocksize) {
		if (sigblock[1] == 0x00) { // type 0, looking for first non-zero byte
			if (sigblock[dataindex] != 0) {
				break;
			}
		}
		else if (sigblock[1] == 0x01) { // type 1, looking for first non-0xff byte + 1
			if (sigblock[dataindex] == 0x00) {
				dataindex++;
				break;
			}
			else if (sigblock[dataindex] != 0xff) {
				std::cerr << "bad byte padding byte for type 1 " << (int)sigblock[dataindex] << std::endl;
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return false;
			}
		}
		else if (sigblock[1] == 0x02) {
			if (sigblock[dataindex] == 0x00) {
				dataindex++;
				break;
			}
		}
		dataindex++;
	}
	if (dataindex == blocksize) {
		std::cerr << "No data found in block " << " " << dataindex << std::endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	if (!sigblock[dataindex] == 0x02) {
		std::cerr << "Unknown digest format " << (int)sigblock[dataindex] << std::endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	ByteVector hashdata = ByteVector(sigblock.length() - dataindex - 1);
	sigblock.copyBytesByIndex(&hashdata, dataindex + 1, sigblock.length() - dataindex - 1, 0);
	
	if (!hashdata.equal(&hash)) {
		std::cerr << "Signature does not match digest " << (int)sigblock[dataindex] << std::endl;
		bn_free_ptrs(&bn_ptrs);
		BN_CTX_free(ctx);
		return false;
	}

	bn_free_ptrs(&bn_ptrs);
	BN_CTX_free(ctx);
	return true;
}

RSAClient::~RSAClient()
{
	if (p != NULL) {
		BN_free(p);
	}
	if (q != NULL) {
		BN_free(q);
	}
	if (n != NULL) {
		BN_free(n);
	}
	if (e != NULL) {
		BN_free(e);
	}
	if (d != NULL) {
		BN_free(d);
	}
}

void RSAClient::print_vals() {
	printf("P:\t%s\n", BN_bn2hex(p));
	printf("Q:\t%s\n", BN_bn2hex(q));
	printf("N:\t%s\n", BN_bn2hex(n));
	printf("D:\t%s\n", BN_bn2hex(d));
}

// copies e and n to initialized BIGNUMs e_out and n_out
// returns false if e or n are not initialized
bool RSAClient::public_key(BIGNUM *e_out, BIGNUM *n_out) {
	if (e == NULL || n == NULL) {
		return false;
	}
	BN_copy(e_out, e);
	BN_copy(n_out, n);
	return true;
}

