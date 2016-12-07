#include "hmq1725.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
/** ADDED FOR HMQ1725 */
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/sph_sha2.h"
#include "sha3/sph_haval.h"


void hmq1725_hash(const char* input, char* output, uint32_t len)
{
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    /** added for HMQ1725 */
    sph_luffa512_context      ctx_luffa;
    sph_cubehash512_context   ctx_cubehash;
    sph_shavite512_context    ctx_shavite;
    sph_simd512_context       ctx_simd;
    sph_echo512_context       ctx_echo;
    sph_hamsi512_context      ctx_hamsi;
    sph_fugue512_context      ctx_fugue;
    sph_shabal512_context     ctx_shabal;
    sph_whirlpool_context     ctx_whirlpool;
    sph_sha512_context        ctx_sha2;
    sph_haval256_5_context    ctx_haval;

    uint32_t mask = 24;
    uint32_t zero = 0;
    
    uint32_t hashA[25], hashB[25];


    sph_bmw512_init(&ctx_blake);
    sph_bmw512 (&ctx_blake, input, len);
    sph_bmw512_close (&ctx_blake, hashA);	//0

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashA, 64);		//0
    sph_whirlpool_close(&ctx_whirlpool, hashB);		//1

    if ((hashB[0] & mask) != zero)
    {
        sph_groestl512_init(&ctx_groestl);
        sph_groestl512 (&ctx_groestl, hashB, 64);	//1
        sph_groestl512_close(&ctx_groestl, hashA);	//2
    }
    else
    {
        sph_skein512_init(&ctx_skein);
        sph_skein512 (&ctx_skein, hashB, 64);	//1
        sph_skein512_close(&ctx_skein, hashA);	//2
    }


    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashA, 64);		//2
    sph_jh512_close(&ctx_jh, hashB);		//3
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashB, 64);	//3
    sph_keccak512_close(&ctx_keccak, hashA);	//4

if ((hashA[0] & mask) != zero)
    {
        sph_blake512_init(&ctx_blake);
        sph_blake512 (&ctx_blake, hashA, 64);		//4
        sph_blake512_close(&ctx_blake, hashB);	//5
    }
    else
    {
        sph_bmw512_init(&ctx_bmw);
        sph_bmw512 (&ctx_bmw, hashA, 64);		//4
        sph_bmw512_close(&ctx_bmw, hashB);		//5
    }

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, hashB, 64);		//5
    sph_luffa512_close(&ctx_luffa, hashA);		//6
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512 (&ctx_cubehash, hashA, 64);		//6
    sph_cubehash512_close(&ctx_cubehash, hashB);	//7
 
if ((hashB[0] & mask) != zero)
    {
        sph_keccak512_init(&ctx_keccak);
        sph_keccak512 (&ctx_keccak, hashB, 64);		//7
        sph_keccak512_close(&ctx_keccak, hashA);	//8
    }
    else
    {
        sph_jh512_init(&ctx_jh);
        sph_jh512 (&ctx_jh, hashB, 64);			//7
        sph_jh512_close(&ctx_jh, hashA);		//8
    }

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hashA, 64);	//8
    sph_shavite512_close(&ctx_shavite, hashB);	//9
        
    sph_simd512_init(&ctx_simd);
    sph_simd512 (&ctx_simd, hashB, 64);			//9
    sph_simd512_close(&ctx_simd, hashA);		//10

if ((hashA[0] & mask) != zero)
    {
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashA, 64);	//10
    sph_whirlpool_close(&ctx_whirlpool, hashB);	//11
    }
    else
    {
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, hashA, 64);	//10
    sph_haval256_5_close(&ctx_haval, hashB);	//11
    }

    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo, hashB, 64);			//11
    sph_echo512_close(&ctx_echo, hashA);		//12

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, hashA, 64);		//12
    sph_blake512_close(&ctx_blake, hashB);		//13

if ((hashB[0] & mask) != zero)
    {
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hashB, 64);	//13
    sph_shavite512_close(&ctx_shavite, hashA);	//14
    }
    else
    {
    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, hashB, 64);		//13
    sph_luffa512_close(&ctx_luffa, hashA);		//14
    }

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi, hashA, 64);		//14
    sph_hamsi512_close(&ctx_hamsi, hashB);		//15

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, hashB, 64);		//16
    sph_fugue512_close(&ctx_fugue, hashA);		//17

if ((hashA[0] & mask) != zero)
    {
    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo, hashA, 64);		//17
    sph_echo512_close(&ctx_echo, hashB);		//18
    }
    else
    {
    sph_simd512_init(&ctx_simd);
    sph_simd512 (&ctx_simd, hashA, 64);		//17
    sph_simd512_close(&ctx_simd, hashB);		//18
    }

    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal, hashB, 64);	//18
    sph_shabal512_close(&ctx_shabal, hashA);	//19

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashA, 64);	//19
    sph_whirlpool_close(&ctx_whirlpool, hashB);	//20

if ((hashB[0] & mask) != zero)
    {
    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, hashB, 64);	//20
    sph_fugue512_close(&ctx_fugue, hashA);	//21
    }
    else
    {
    sph_sha512_init(&ctx_sha2);
    sph_sha512 (&ctx_sha2, hashB, 64);		//20
    sph_sha512_close(&ctx_sha2, hashA);		//21
    }

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashA, 64);	//21
    sph_groestl512_close(&ctx_groestl, hashB);	//22

    sph_sha512_init(&ctx_sha2);
    sph_sha512 (&ctx_sha2, hashB, 64);		//22
    sph_sha512_close(&ctx_sha2, hashA);		//23

if ((hashA[0] & mask) != zero)
    {
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, hashA, 64);	//23
    sph_haval256_5_close(&ctx_haval, hashB);	//24
    }
    else
    {
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashA, 64);	//23
    sph_whirlpool_close(&ctx_whirlpool, hashB);	//24
    }

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashB, 64);		//24
    sph_bmw512_close(&ctx_bmw, hashA);		//25




	memcpy(output, hashA, 32);

}
