#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sha3/sph_blake.h>
#include <sha3/sph_bmw.h>
#include <sha3/sph_groestl.h>
#include <sha3/sph_jh.h>
#include <sha3/sph_keccak.h>
#include <sha3/sph_skein.h>
#include <sha3/sph_luffa.h>
#include <sha3/sph_cubehash.h>
#include <sha3/sph_shavite.h>
#include <sha3/sph_simd.h>
#include <sha3/sph_echo.h>
#include <sha3/sph_hamsi.h>
#include <sha3/sph_fugue.h>
#include <sha3/sph_shabal.h>
#include <sha3/sph_whirlpool.h>
#include <sha3/gost_streebog.h>
#include <sha3/sph_haval.h>
#include <sha3/sph_sha2.h>

#define HASH_FUNC_BASE_TIMESTAMP_1 1492973331 // Bitcore  Genesis
#define HASH_FUNC_COUNT_1 8
#define HASH_FUNC_COUNT_2 8
#define HASH_FUNC_COUNT_3 7
#define HASH_FUNC_VAR_1 3333
#define HASH_FUNC_VAR_2 2100
#define HASH_FUNC_COUNT_PERMUTATIONS_7 5040
#define HASH_FUNC_COUNT_PERMUTATIONS 40320

#define _ALIGN(x) __attribute__ ((aligned(x)))

// helpers
inline void swap(int *a, int *b) {
	int c = *a;
	*a = *b;
	*b = c;
}

static void reverse(int *pbegin, int *pend) {
	while ( (pbegin != pend) && (pbegin != --pend) )
		swap(pbegin++, pend);
}

static void next_permutation(int *pbegin, int *pend) {
	if (pbegin == pend)
		return;

	int *i = pbegin;
	++i;
	if (i == pend)
		return;

	i = pend;
	--i;

	while (1) {
		int *j = i;
		--i;

		if (*i < *j) {
			int *k = pend;

			while (!(*i < *--k))
				/* pass */;

			swap(i, k);
			reverse(j, pend);
			return; // true
		}

		if (i == pbegin) {
			reverse(pbegin, pend);
			return; // false
		}
	}
}
// helpers

void timetravel_hash(const char* input, char* output, uint32_t len)
{
	uint32_t _ALIGN(64) hash[128]; // 16 bytes * HASH_FUNC_COUNT
	uint32_t *hashA, *hashB;
	uint32_t dataLen = 64;
	uint32_t *work_data = (uint32_t *)input;
	const uint32_t timestamp = work_data[17];

    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    sph_luffa512_context     ctx_luffa;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_hamsi512_context     ctx_hamsi;
    sph_fugue512_context     ctx_fugue;
    sph_shabal512_context    ctx_shabal;
    sph_whirlpool_context    ctx_whirlpool;
    sph_sha512_context       ctx_sha512;
    sph_gost512_context      ctx_gost;
    sph_haval256_5_context    ctx_haval;

uint32_t permutation_1[HASH_FUNC_COUNT_1];
    uint32_t permutation_2[HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1];
    uint32_t permutation_3[HASH_FUNC_COUNT_3 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1];
            //Init1
            for (uint32_t i = 1; i < HASH_FUNC_COUNT_1; i++) {
                permutation_1[i] = i;
            }

            //Init2
            for (uint32_t i = HASH_FUNC_COUNT_1; i < HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1; i++) {
                permutation_2[i] = i;
            }

            //Init3
            for (uint32_t i = HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2; i < HASH_FUNC_COUNT_3 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_1; i++) {
                permutation_3[i] = i;
            }

            uint32_t steps_1 = (timestamp - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS_7;
            for (uint32_t i = 0; i < steps_1; i++) {
                std::next_permutation(permutation_1, permutation_1 + HASH_FUNC_COUNT_1);
            }

            uint32_t steps_2 = (timestamp+ HASH_FUNC_VAR_1 - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS;
            for (uint32_t i = 0; i < steps_2; i++) {
                std::next_permutation(permutation_2 + HASH_FUNC_COUNT_1, permutation_2 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2);
            }

            uint32_t steps_3 = (timestamp+ HASH_FUNC_VAR_2 - HASH_FUNC_BASE_TIMESTAMP_1) % HASH_FUNC_COUNT_PERMUTATIONS_7;
            for (uint32_t i = 0; i < steps_3; i++) {
                std::next_permutation(permutation_3 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2, permutation_3 + HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_3);
            }


dataLen = len;
hashA = work_data;
hashB = &hash[0];

sph_blake512_init(&ctx_blake);
sph_blake512(&ctx_blake, hashA, dataLen);
sph_blake512_close(&ctx_blake, hashB);

	for (uint32_t i = 1; i < HASH_FUNC_COUNT; i++) {
		dataLen = 64;
		hashA = &hash[16 * (i - 1)];
		hashB = &hash[16 * i];

		switch(permutation[i]) {
			case 1:
				sph_echo512_init(&ctx_echo);
				sph_echo512 (&ctx_echo, hashA, dataLen);
				sph_echo512_close(&ctx_echo, hashB);

				sph_blake512_init(&ctx_blake);
				sph_blake512(&ctx_blake, hashB, dataLen);
				sph_blake512_close(&ctx_blake, hashB);
				break;
			case 2:
				sph_simd512_init(&ctx_simd);
				sph_simd512 (&ctx_simd, hashA, dataLen);
				sph_simd512_close(&ctx_simd, hashB);

				sph_bmw512_init(&ctx_bmw);
				sph_bmw512(&ctx_bmw, hashB, dataLen);
				sph_bmw512_close(&ctx_bmw, hashB);
				break;
			case 3:
				sph_groestl512_init(&ctx_groestl);
				sph_groestl512 (&ctx_groestl, hashA, dataLen);
				sph_groestl512_close(&ctx_groestl, hashB);
				break;
			case 4:
				sph_whirlpool512_init(&ctx_whirlpool);
				sph_whirlpool512 (&ctx_whirlpool, hashA, dataLen);
				sph_whirlpool512_close(&ctx_whirlpool, hashB);
				break;

				sph_jh512_init(&ctx_jh);
				sph_jh512 (&ctx_jh, hashB, dataLen);
				sph_jh512_close(&ctx_jh, hashB);
				break;
			case 5:
				sph_gost512_init(&ctx_gost);
				sph_gost512 (&ctx_gost, hashA, dataLen);
				sph_gost512_close(&ctx_gost, hashB);

				sph_keccak512_init(&ctx_keccak);
				sph_keccak512 (&ctx_keccak, hashB, dataLen);
				sph_keccak512_close(&ctx_keccak, hashB);
				break;
			case 6:
				sph_fugue512_init(&ctx_fugue);
				sph_fugue512 (&ctx_fugue, hashA, dataLen);
				sph_fugue512_close(&ctx_fugue, hashB);

				sph_skein512_init(&ctx_skein);
				sph_skein512 (&ctx_skein, hashB, dataLen);
				sph_skein512_close(&ctx_skein, hashB);
				break;
			case 7:
				sph_shavite512_init(&ctx_shavite);
				sph_shavite512(&ctx_shavite, hashA, dataLen);
				sph_shavite512_close(&ctx_shavite, hashB);

				sph_luffa512_init(&ctx_luffa);
				sph_luffa512 (&ctx_luffa, hashB, dataLen);
				sph_luffa512_close(&ctx_luffa, hashB);
				break;
		}
	}

            for (int i = HASH_FUNC_COUNT_1; i < HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2; i++) {
		hashA = &hash[16 * (i - 1)];
		hashB = &hash[16 * i];

                switch (permutation_2[i]) {
			case 8:
				sph_whirlpool512_init(&ctx_whirlpool);
				sph_whirlpool512 (&ctx_whirlpool, hashA, dataLen);
				sph_whirlpool512_close(&ctx_whirlpool, hashB);

				sph_cubehash512_init(&ctx_cubehash);
				sph_cubehash512 (&ctx_cubehash, hashB, dataLen);
				sph_cubehash512_close(&ctx_cubehash, hashB);
				break;
			case 9:
				sph_jh512_init(&ctx_jh);
				sph_jh512 (&ctx_jh, hashA, dataLen);
				sph_jh512_close(&ctx_jh, hashB);

				sph_shavite512_init(&ctx_shavite);
				sph_shavite512(&ctx_shavite, hashB, dataLen);
				sph_shavite512_close(&ctx_shavite, hashB);
				break;
			case 10:
				sph_blake512_init(&ctx_blake);
				sph_blake512(&ctx_blake, hashA, dataLen);
				sph_blake512_close(&ctx_blake, hashB);

				sph_simd512_init(&ctx_simd);
				sph_simd512 (&ctx_simd, hashB, dataLen);
				sph_simd512_close(&ctx_simd, hashB);
				break;
			case 11:
				sph_shabal512_init(&ctx_shabal);
				sph_shabal512 (&ctx_shabal, hashA, dataLen);
				sph_shabal512_close(&ctx_shabal, hashB);

				sph_echo512_init(&ctx_echo);
				sph_echo512 (&ctx_echo, hashB, dataLen);
				sph_echo512_close(&ctx_echo, hashB);
				break;
			case 12:
				sph_hamsi512_init(&ctx_hamsi);
				sph_hamsi512 (&ctx_hamsi, hashA, dataLen);
				sph_hamsi512_close(&ctx_hamsi, hashB);
				break;
			case 13:
				sph_bmw512_init(&ctx_bmw);
				sph_bmw512 (&ctx_bmw, hashA, dataLen);
				sph_bmw512_close(&ctx_bmw, hashB);
				break;

				sph_fugue512_init(&ctx_fugue);
				sph_fugue512 (&ctx_fugue, hashB, dataLen);
				sph_fugue512_close(&ctx_fugue, hashB);
				break;
			case 14:
				sph_keccak512_init(&ctx_keccak);
				sph_keccak512 (&ctx_keccak, hashA, dataLen);
				sph_keccak512_close(&ctx_keccak, hashB);

				sph_shabal512_init(&ctx_shabal);
				sph_shabal512 (&ctx_shabal, hashB, dataLen);
				sph_shabal512_close(&ctx_shabal, hashB);
				break;
			case 15:
				sph_luffa512_init(&ctx_luffa);
				sph_luffa512 (&ctx_luffa, hashA, dataLen);
				sph_luffa512_close(&ctx_luffa, hashB);

				sph_whirlpool512_init(&ctx_whirlpool);
				sph_whirlpool512 (&ctx_whirlpool, hashB, dataLen);
				sph_whirlpool512_close(&ctx_whirlpool, hashB);
				break;
		}

	}

            for (int i = HASH_FUNC_COUNT_2; i < HASH_FUNC_COUNT_1 + HASH_FUNC_COUNT_2 + HASH_FUNC_COUNT_3; i++) {
		hashA = &hash[16 * (i - 1)];
		hashB = &hash[16 * i];

                switch (permutation_3[i]) {
			case 16:
				sph_sha512_init(&ctx_sha512);
				sph_sha512 (&ctx_sha512, hashA, dataLen);
				sph_sha512_close(&ctx_sha512, hashB);

				sph_haval256_5_init(&ctx_haval);
				sph_haval256_5 (&ctx_haval, hashB, dataLen);
				sph_haval256_5_close(&ctx_haval, hashB);
				break;
			case 17:
				sph_skein512_init(&ctx_skein);
				sph_skein512 (&ctx_skein, hashA, dataLen);
				sph_skein512_close(&ctx_skein, hashB);

				sph_groestl512_init(&ctx_groestl);
				sph_groestl512 (&ctx_groestl, hashB, dataLen);
				sph_groestl512_close(&ctx_groestl, hashB);
				break;
			case 18:
				sph_simd512_init(&ctx_simd);
				sph_simd512 (&ctx_simd, hashA, dataLen);
				sph_simd512_close(&ctx_simd, hashB);

				sph_hamsi512_init(&ctx_hamsi);
				sph_hamsi512 (&ctx_hamsi, hashB, dataLen);
				sph_hamsi512_close(&ctx_hamsi, hashB);
				break;
			case 19:
				sph_gost512_init(&ctx_gost);
				sph_gost512 (&ctx_gost, hashA, dataLen);
				sph_gost512_close(&ctx_gost, hashB);

				sph_haval256_5_init(&ctx_haval);
				sph_haval256_5 (&ctx_haval, hashB, dataLen);
				sph_haval256_5_close(&ctx_haval, hashB);
				break;
			case 20:
				sph_cubehash512_init(&ctx_cubehash);
				sph_cubehash512 (&ctx_cubehash, hashA, dataLen);
				sph_cubehash512_close(&ctx_cubehash, hashB);

				sph_sha512_init(&ctx_sha512);
				sph_sha512 (&ctx_sha512, hashB, dataLen);
				sph_sha512_close(&ctx_sha512, hashB);
				break;
			case 21:
				sph_echo512_init(&ctx_echo);
				sph_echo512 (&ctx_echo, hashA, dataLen);
				sph_echo512_close(&ctx_echo, hashB);

				sph_shavite512_init(&ctx_shavite);
				sph_shavite512 (&ctx_shavite, hashB, dataLen);
				sph_shavite512_close(&ctx_shavite, hashB);
				break;
			case 22:
				sph_luffa512_init(&ctx_luffa);
				sph_luffa512 (&ctx_luffa, hashA, dataLen);
				sph_luffa512_close(&ctx_luffa, hashB);

				sph_shabal512_init(&ctx_shabal);
				sph_shabal512 (&ctx_shabal, hashB, dataLen);
				sph_shabal512_close(&ctx_shabal, hashB);
				break;
		}

	}
			

	memcpy(output, &hash[352], 32);
}

