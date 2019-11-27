#include "RSAClient.h"
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
			printf("%d %d %d\n", i, input->length(), datablock_size);
			size_t thislen = (input->length() - i < datablock_size ? input->length() - i : datablock_size);
			size_t padlen = blocksize - thislen - 3;
			inblock[0] = 0x00;
			inblock[1] = (byte) (0xff & padtype);
			for (size_t j = 2; j < padlen + 2; j++) {
				if (padtype == 1) {
					inblock[j] = 0xff;
				}
				if (padtype == 2) {
					inblock[j] = (byte) rand_range(1, 255);
				}
				else {
					inblock[j] = 0x00;
				}
			}
			inblock[2 + padlen] = 0x00;
			input->copyBytesByIndex(&inblock, i, thislen, 3 + padlen);

			printf("Inblock:\n");
			inblock.printHexStrByBlocks(16);

			BIGNUM *in = bn_from_bytevector(&inblock, &bn_ptrs);

			if (!BN_mod_exp(out, in, e, n, ctx)) {
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return false;
			}

			bn_to_bytevector(out, &outblock);
			printf("Outblock %d %d\n", outblock.length(), BN_num_bits(out));
			outblock.printHexStrByBlocks(16);

			ByteVector decrypt_test = ByteVector();
			BIGNUM *test = BN_new();
			bn_add_to_ptrs(test, &bn_ptrs);
			if (!BN_mod_exp(test, out, d, n, ctx)) {
				bn_free_ptrs(&bn_ptrs);
				BN_CTX_free(ctx);
				return false;
			}
			bn_to_bytevector(test, &decrypt_test);
			decrypt_test.printHexStrByBlocks(16);

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

		for (size_t i = 0; i < encrypted->length(); i += blocksize) {
			encrypted->copyBytesByIndex(&inblock, i, blocksize, 0);
			
			printf("Position %d:\nInblock:\n", i);
			inblock.printHexStrByBlocks(16);

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
				temp.copyBytesByIndex(&outblock, 0, temp.length(), blocksize - 1 - temp.length());
			} 

			printf("Outblock:\n");
			outblock.printHexStrByBlocks(16);

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
			outblock.copyBytesByIndex(output, dataindex, outblock.length() - dataindex, (i/blocksize)*datablock_size);
			
 		}

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
