/***************************************************************************
                                                                           *
Copyright 2013 CertiVox UK Ltd.                                           *
                                                                           *
This file is part of CertiVox MIRACL Crypto SDK.                           *
                                                                           *
The CertiVox MIRACL Crypto SDK provides developers with an                 *
extensive and efficient set of cryptographic functions.                    *
For further information about its features and functionalities please      *
refer to http://www.certivox.com                                           *
                                                                           *
* The CertiVox MIRACL Crypto SDK is free software: you can                 *
  redistribute it and/or modify it under the terms of the                  *
  GNU Affero General Public License as published by the                    *
  Free Software Foundation, either version 3 of the License,               *
  or (at your option) any later version.                                   *
                                                                           *
* The CertiVox MIRACL Crypto SDK is distributed in the hope                *
  that it will be useful, but WITHOUT ANY WARRANTY; without even the       *
  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. *
  See the GNU Affero General Public License for more details.              *
                                                                           *
* You should have received a copy of the GNU Affero General Public         *
  License along with CertiVox MIRACL Crypto SDK.                           *
  If not, see <http://www.gnu.org/licenses/>.                              *
                                                                           *
You can be released from the requirements of the license by purchasing     *
a commercial license. Buying such a license is mandatory as soon as you    *
develop commercial activities involving the CertiVox MIRACL Crypto SDK     *
without disclosing the source code of your own applications, or shipping   *
the CertiVox MIRACL Crypto SDK with a closed source product.               *
                                                                           *
***************************************************************************/
/*
 * Implementation of BPS Format Preserving Encryption
 *
 * See "BPS: a Format Preserving Encryption Proposal" by E. Brier, T. Peyrin and J. Stern
 *
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/bps/bps-spec.pdf
 *
 * Uses AES internally
 *
 * Author: M. Scott 2012/2015
 */

#include <stdlib.h>
#include <jni.h>
#include <string.h>
#include "miracl.h"
#include <stdio.h>
#include <math.h>

/* Define FPE_TEST to activate test main program and run test vectors */
/* Link with mraes.c */
/* gcc -O2 mrfpe.c mraes.c -o mrfpe.exe */
 #define FPE_TEST 

#define UINT32 mr_unsign32 /* 32-bit unsigned type */
#define W 8 /* recommended number of rounds */
#define BLOCK_SIZE 16 /* 16 Byte Blocks - AES */
#define ENCRYPT 0
#define DECRYPT 1



/////////////////////////////////////////////START - for FEA code adjustment///////////////////////////////////////////////

/////////////////////////////////////////////START - for FEA code adjustment///////////////////////////////////////////////




//////////////////////////////////////////////////////////////////////////////////

//type definition - begin                                          //

//////////////////////////////////////////////////////////////////////////////////

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;



#define ROUND_NUM 18




//////////////////////////////////////////////////////////////////////////////////

// Look Up Table - Start

//////////////////////////////////////////////////////////////////////////////////
u64 LUT[256] = {
        0xe64ef6412359c370,
        0x73a77b594ae51ab8,
        0x34497b9c45310c9d,
        0x91027b420f1093e8,
        0x8c5bf6338167e7e0,
        0x4b8d00e18715d878,
        0x506e000ea2594d15,
        0x03a8000999edab2c,
        0x6821f6388a62183a,
        0x67b2f653e43da861,
        0x7abef66e3e2c380d,
        0x64417b2c2f97a5a0,
        0x39f000ab444b29a5,
        0xee2c7b594a601a33,
        0x5d647b3557095051,
        0x40077bc0380347fa,
        0xa448f67bf6297b29,
        0x0f66002d1b4e7518,
        0xc2a3f6d52cc56559,
        0x6e00f64a4bcb6eb0,
        0x271c7b931d3ad267,
        0x3c2700b46c386360,
        0x32a200b46cbd6356,
        0xeabd004d7e243699,
        0x2cc300a2ab547e6f,
        0x3b2900cfc6a2f387,
        0x331100991253442f,
        0x3e97f6bad265d5ad,
        0xa3107b78c34b42bb,
        0xd7e8f614080b4e58,
        0xac267b931d30d25d,
        0xe985f64a4b466e2b,
        0x9f30006c680fcf21,
        0x840c001b5a60901d,
        0xf67b000000f600f6,
        0x4c8ef602471d69ec,
        0xb006f69f78fb4586,
        0x923af645425fcc56,
        0x8345f6182711573e,
        0x5b2b7b11d5b2156f,
        0x58837b083c36db43,
        0x481f7bf67b52f652,
        0x6b21005f3f081b8a,
        0xad5ef696500e0bcb,
        0x66b10032243517ed,
        0x88ec7b27262b0346,
        0x2cfaf6841e9b26da,
        0x7517005f3f121b05,
        0x19257b4ba8823e28,
        0xba5400bd052f0e96,
        0x667a7b50b1ee6f82,
        0x5515f61d3002f91d,
        0xfb22f60fff101dfe,
        0xf3440068d809c63b,
        0x06500012326956e7,
        0x5abc7b2c2f1ca525,
        0x4dc60005096ca25a,
        0xa77ff6841e162655,
        0x45ae00cfc61df302,
        0x27530075908109d2,
        0xed6500561711e154,
        0x1646f6609cbf5c02,
        0x2005007e29f3b412,
        0xb47500ab44c62920,
        0x54dd7b1a6e24c0af,
        0x167d7b420f06936d,
        0x11d6f63381ece765,
        0xe5167b3ef00a8a91,
        0xddc7f626c97433ce,
        0x109e7b304e9daef7,
        0x0e6800487529503f,
        0x491d7bdb21e8662b,
        0x18ed0048753305ba,
        0x0c2f0024f3d23b5d,
        0x3af1f6cc9353ba19,
        0x1a26006c688acf9c,
        0x764f7b6272615473,
        0x6a5af65c0cb9531c,
        0xb6e5f6b139642a6d,
        0x1a5df64edbd10607,
        0x47e700f34803bde4,
        0x5613f60247986967,
        0xe06ff62f6261de89,
        0x119f00510ea53f6b,
        0x0101f621c0080274,
        0x1545003f4db75aff,
        0xff02001b5adb9027,
        0x0270f606669e724d,
        0xa8b7008751655fc3,
        0x21030063cf18245c,
        0xc882f6e7ed2e4a40,
        0x961a00510e2a3ff0,
        0x413ff6c36b520f68,
        0xf09c005f3f8d1b0f,
        0x316af6b1396e2a77,
        0xf7b37b0333453964,
        0xdc8f7b2396256b60,
        0x6579f62f62e6de0e,
        0x7716f665a5b08d52,
        0x261bf6725d324164,
        0x4307f6e7ed384a4a,
        0x9bc1f6609c445cf8,
        0x25e37b6f2a540885,
        0x05e1002d1b44750e,
        0xb91cf6bad2e0d528,
        0x12d77b5441f478d9,
        0xc16b7bd2f9762ceb,
        0xf8ebf60666237243,
        0x1f047b5d69eb230f,
        0xd578000ea2de4d0b,
        0xe26e7b35578e50d6,
        0xfc5a0012325f566c,
        0x5c63f61408014edd,
        0x281a7b78c3d04240,
        0x30327bae061f6209,
        0x53dcf6f9ae1c2f3b,
        0xab5f0090eae1997e,
        0x140df63c1a682120,
        0x223b7b6602675dca,
        0x36117bc03888477f,
        0xf20cf665a52b8d5c,
        0x0000000000000000,
        0xcb2af6f015aa84fb,
        0xf40b7b6b0b58ffa9,
        0x7f657b0ccc46e415,
        0x2e33f6a811f2f0bc,
        0x46e67bd2f96c2c70,
        0xce61f6f9ae262fb6,
        0x130ff6570343b147,
        0xe1360032243f1768,
        0x2373f66935b69638,
        0xcc6200f348f9bd69,
        0x4a55f6de54379f0a,
        0x51357b11d53715f4,
        0x177e0063cf0e24e1,
        0x4e3500ea20021233,
        0x9951005a3617eaab,
        0x6959003bbdb151a8,
        0xd9587b1a6ea9c034,
        0x60d2002063cc3206,
        0x39b97bc96004813a,
        0x1d94f657034db1c2,
        0x233c0087516f5f3e,
        0x61d3f64123d4c37a,
        0x52a47bf67bcdf6cd,
        0x5e2bf6388a5818bf,
        0x8924f62a597a3c25,
        0xd3087b083c40dbbe,
        0x610a7b23961b6be5,
        0x3d5f7bb79f169c3f,
        0x4f6d7bed53514b12,
        0xafce7b9c45ac0c18,
        0x903b003f4d325a09,
        0x07177b1565b81e55,
        0xebf57b50b1736f07,
        0xd440f60b6f8f142c,
        0x95e2f64edb4c0611,
        0x084ff61827075734,
        0x4b567bff143f300d,
        0x7137f653e447a86b,
        0x2bc27b815c4ced6c,
        0x04a9f62a59f53c2f,
        0x1e957b78c3554236,
        0xd82000173b5a87c6,
        0xb5ad7bae0615628e,
        0x443f00ea20871229,
        0x4f36f60b6f0a14a7,
        0x9a897b5d69662319,
        0xb8557bb79f919c49,
        0x1ecc005a369cea30,
        0xc54bf6de54419f14,
        0x3749f6c36bd70f5e,
        0xe715004456a8fcde,
        0x06197b304e22ae7c,
        0x2a8a007e296eb48d,
        0x08180036b4c020c9,
        0xc74a7be4badf1161,
        0x68ea0056171be1cf,
        0x620b00445623fc59,
        0x564d0020635132fc,
        0x2dfb7ba5dea3b74e,
        0x09507b39e70f5937,
        0x574b000509e7a2d5,
        0x30690090ea669903,
        0xbe347bc960fa8130,
        0x1c25f6725d2841e9,
        0x6c597b6272575469,
        0xa2d8007590fc094d,
        0x541400fce16b681a,
        0x0f2f7b4ba8073e1e,
        0xdeff0029fcc36c3c,
        0x354a00bd05390e11,
        0x3510f69f7880450b,
        0x6f38004d7e1a361e,
        0x2854f69650890b46,
        0x420600c62d304847,
        0x1b5e7b6f2ad9080a,
        0x42407be4ba5a11dc,
        0x726f00561796e14a,
        0x1fcdf67bf6a47ba4,
        0x6ec90068d884c645,
        0x24747b8a84be27ac,
        0xc3db00d85f142d38,
        0xa6477b815cc7ed76,
        0x7e2d00099968ab36,
        0xcaf27bed535b4b1c,
        0x18b67b66025d5d4f,
        0xbf6cf6cc9349ba9e,
        0xfd927b15653d1e4b,
        0x85447b1e8dafc98b,
        0x9d317b6602e25d45,
        0x04e07b0ccc3ce49a,
        0x5f63003bbd36512d,
        0x40d0f6de54bc9f8f,
        0x5d2a00173b50874b,
        0x809df60fff951d83,
        0x0d30f64542daccd1,
        0xbdfc00c62dab4851,
        0x7039f66e3e223892,
        0x63437b47180135c7,
        0x37807ba5de1eb758,
        0x6dc87b47187c3542,
        0x2f31f68db7176095,
        0x59840029fc3e6cb7,
        0x5034f6f0152f8480,
        0x5f9af61d307df998,
        0x2e6a7b8a84392727,
        0x6a207b3ef0008a16,
        0x471ef6d52c4a654f,
        0x4dfdf6e7edb34ac5,
        0xb13e00a2ab4a7e65,
        0x8d930036b445204e,
        0x87b40024f34d3bd8,
        0x46aff6f015258405,
        0x0bf7f621c08302ef,
        0x0d677b272621033c,
        0xa0687b6f2a5e0800,
        0xef64f65c0c3e53a1,
        0x784e0068d8ffc6c0,
        0x291b009912d844b4,
        0x8ecb7b39e794592d,
        0xcf9900fce1756824,
        0xd0d17bff14c43003,
        0x0a88f63c1a5e2116,
        0x003a7b1e8d2ac906,
        0x25acf68db70d601a,
        0x9e69f669353196b3,
        0x3e6000d85f1e2d42,
        0x3f987bdb216d6621,
        0x584cf626c9ef3349,
        0x38b8f6a8116df037,
        0xc61200e18790d8f3,
        0x7bf60000007b007b,
        0x97527b544179785e,
        0x7c2e7b0333ca395a,
        0x6f017b6b0bd3ff24,
};

//////////////////////////////////////////////////////////////////////////////////

// Look Up Table - End

//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////

//type definition - end                                             //

//////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////

// functions for generic operation - begin                              //

//////////////////////////////////////////////////////////////////////////////////

void XOR_ARY8(u8* out, u8* in1, u8* in2) {
    int i = 0;

    for (i = 0; i<8; i++) {
        out[i] = in1[i] ^ in2[i];
    }
}

void XOR_ARY4(u8* out, u8* in1, u8* in2) {
    int i = 0;

    for (i = 0; i<4; i++) {
        out[i] = in1[i] ^ in2[i];
    }
}

void COPY_ARY8(u8* out, u8* in) {
    int i = 0;

    for (i = 0; i<8; i++) {
        out[i] = in[i];
    }
}

void ZERO_ARY8(u8* inout) {
    int i = 0;
    for (i = 0; i<8; i++) {
        inout[i] = 0;
    }
}

//////////////////////////////////////////////////////////////////////////////////

// functions for generic operation - begin                              //

//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
//StrToNum, NumToStr   - begin                                       //
//////////////////////////////////////////////////////////////////////////////////

void NumToBits(u64 q, u8* p)
{
    int i;
    for (i = 7; i >= 0; --i)
    {
        p[i] = q & 0xff;
        q >>= 8;
    }
}

void BitsToNum(u64* y, u8* p)
{
    int i = 0;
    int j = 0;
    u64 jin16[16] = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
    for (i = 15; i >= 1; i--) {
        jin16[i - 1] = jin16[i] * 16;
    }

    for (i = 7; i >= 0; i--) {
        *y += ((p[i] >> 4)*jin16[2 * i] + (p[i] & 0x0f)*jin16[2 * i + 1]);
    }
}


void NumToBits_4(u64 x, u8* p)
{
    int i;
    for (i = 3; i >= 0; --i)
    {
        p[i] = x & 0xff;
        x >>= 8;
    }
}


void BitsToNum_4(u64* y, u8* p)
{
    int i = 0;
    u64 jin16[8] = { 1, 1, 1, 1, 1, 1, 1, 1 };
    for (i = 7; i >= 1; i--) {
        jin16[i - 1] = jin16[i] * 16;
    }

    for (i = 3; i >= 0; i--) {
        *y += ((p[i] >> 4)*jin16[2 * i] + (p[i] & 0x0f)*jin16[2 * i + 1]);
    }
}



//////////////////////////////////////////////////////////////////////////////////
//NumToBits, BitsToNum declaration   - end                                       //
//////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////
//StrToNum, NumToStr   - start                                       //
//////////////////////////////////////////////////////////////////////////////////

void StrToNum(u64* x, u8* var) {
    // 7022066633808028452 --> asdf!@#$ (변형한 것)
    int i = 0;
    u64 mull = 1;

    for (i = 0; i < 8; i++) {
        //printf("%llu\n", mull);
        *x += var[7 - i] * mull;
        mull = mull << 8;
    }

}

void NumToStr(u64* x, u8* var_after) {
    //72057594037927936 == 256^8
    int i = 0;
    u64 num = 0;
    u64 mull = 72057594037927936;
    //u64 mull = 1;

    for (i = 0; i < 8; i++) {
        var_after[i] = (char)(*x / (mull));
        *x = *x % (mull);
        mull = mull >> 8;

        //printf("%c", var_after[i]);
    }
}

void StrToNum_4(u64* x, u8* var) {
    // 7022066633808028452 --> asdf!@#$ (변형한 것)
    int i = 0;
    u64 mull = 1;

    for (i = 0; i < 4; i++) {
        //printf("%llu\n", mull);
        *x += var[3 - i] * mull;
        mull = mull << 8;
    }

}


void NumToStr_4(u64* x, u8* var_after) {
    //72057594037927936 == 256^7
    //16777216 == 256^3
    int i = 0;
    u64 num = 0;
    u64 mull = 16777216;
    //u64 mull = 1;

    for (i = 0; i < 4; i++) {
        var_after[i] = (char)(*x / (mull));
        *x = *x % (mull);
        mull = mull >> 8;

        //printf("%c", var_after[i]);
    }

}


//////////////////////////////////////////////////////////////////////////////////
//StrToNum, NumToStr   - end                                       //
//////////////////////////////////////////////////////////////////////////////////

void use_box(u8* in1){
    int i=0;
    u8 in2[8] = {0,};
    u64 Sum=0;

    for(i=0; i<8; i++){
        in2[i] = in1[i];
        in1[i] = 0;
    }

    Sum = LUT[in2[0]] ^
          (  (LUT[in2[1]] << 8) ^ (LUT[in2[1]] >> 56) ) ^
          (  (LUT[in2[2]] << 16) ^ (LUT[in2[2]] >> 48) ) ^
          (  (LUT[in2[3]] << 24) ^ (LUT[in2[3]] >> 40) ) ^
          (  (LUT[in2[4]] << 32) ^ (LUT[in2[4]] >> 32) ) ^
          (  (LUT[in2[5]] << 40) ^ (LUT[in2[5]] >> 24) ) ^
          (  (LUT[in2[6]] << 48) ^ (LUT[in2[6]] >> 16) ) ^
          (  (LUT[in2[7]] << 56) ^ (LUT[in2[7]] >> 8) );

    NumToBits(Sum, in1);

}


void use_box_4(u8* in1){
    int i=0;
    u8 in2[4] = {0,};
    u64 Sum=0;

    for(i=0; i<4; i++){
        in2[i] = in1[i];
        in1[i] = 0;
    }

    Sum = LUT[in2[0]] ^
          (  (LUT[in2[1]] << 8) ^ (LUT[in2[1]] >> 24) ) ^
          (  (LUT[in2[2]] << 16) ^ (LUT[in2[2]] >> 16) ) ^
          (  (LUT[in2[3]] << 24) ^ (LUT[in2[3]] >> 8) ) ;

    NumToBits_4(Sum, in1);

}


//////////////////////////////////////////////////////////////////////////////////
// functions for TBC_KS operation - begin                              //
// number of round                                                //
//       128      192      256                                          //
//type1   12      14       16                                          //
//type2   18      21       24                                          //
//////////////////////////////////////////////////////////////////////////////////

void TBC_KS(u8(*RKA)[8], u8(*RKB)[8], u8* K, u8 n) {

    u8 RC2_128[9][8] = {

            0xAF,0xF6,0xF2,0x03,0x98,0xB3,0xE3,0xC9,

            0x2D,0xB6,0x98,0x72,0x26,0x43,0xF3,0x40,

            0x2B,0xFA,0xAA,0x8B,0x5B,0x17,0x0D,0x8A,

            0x98,0xAC,0xEB,0x6D,0x20,0x76,0xB8,0xE7,

            0x10,0x1B,0xFA,0x4A,0xFB,0x52,0x95,0x55,

            0x44,0x21,0x38,0xC1,0x35,0xAE,0x2E,0xED,

            0x25,0xB8,0x69,0x11,0x29,0x3B,0x57,0x27,

            0xC5,0xE8,0x4A,0x22,0x16,0xCA,0x96,0x3E,

            0x7E,0x38,0x7C,0x31,0x11,0xDA,0xCB,0x1A

    };
    u8 KA[8] = { 0, };
    u8 KB[8] = { 0, };
    u8 KC[8] = { 0, };
    u8 KD[8] = { 0, };

    u8 X[8] = { 0, };
    u8 Y[8] = { 0, };

    u8 r = ROUND_NUM;                  //static for type2 + 128-bit key
    u8 i = 0;
    u8 j = 0;

    COPY_ARY8(KA, &K[8]);         //init (K; Ka, Kb, Kc, Kd) : static for type2 + 128-bit key
    COPY_ARY8(KB, &K[0]);


    for (i = 0; i<(r / 2); i++) {
        XOR_ARY8(X, KA, KC);         //X ← Ka^Kc^RCtype;
        XOR_ARY8(X, X, RC2_128[i]);

        //SBL(X);                  //X ← SBL(X);
        //DL(X);                  //X ← DL(X);
        use_box(X);               // Using LUT instead SBL(). DL()

        XOR_ARY8(Y, KB, KD);         //Y ← Kb^Kd^n^X;
        Y[0] = Y[0] ^ n;
        XOR_ARY8(Y, Y, X);

        //SBL(Y);                  //Y ← SBL(Y);
        //DL(Y);                  //Y ← DL(Y);
        use_box(Y);               // Using LUT instead SBL(). DL()

        //printf("\n");  //using in test

        XOR_ARY8(X, X, Y);         //X ← X^Y;
        XOR_ARY8(KA, KA, X);         //Ka ← Ka^X;    Kb ← Kb^Y;
        XOR_ARY8(KB, KB, Y);


        XOR_ARY8(KC, KC, X);         //Kc ← Kc^X;    Kd ← Kd^Y;
        XOR_ARY8(KD, KD, Y);

        XOR_ARY8(KC, KC, KD);         //Kc ← Kc^Kd;    Kd ← Kd^Kc;
        XOR_ARY8(KD, KD, KC);

        for (j = 0; j<8; j++) {
            RKA[2 * i][j] = KA[j];
            RKA[2 * i + 1][j] = KC[j];
            RKB[2 * i][j] = KB[j];
            RKB[2 * i + 1][j] = KD[j];
        }
    }
    /*
    printf("\n");
    for(i=0; i<18; i++){
    printf("RKA[%d] : ",i);
    for(j=0; j<8; j++){
    printf("%x\t",RKA[i][j]);
    }
    printf("\n");
    }
    printf("\n");
    for(i=0; i<18; i++){
    printf("RKB[%d] : ",i);
    for(j=0; j<8; j++){
    printf("%x\t",RKB[i][j]);
    }
    printf("\n");
    }*/  // check value
}

//////////////////////////////////////////////////////////////////////////////////

// functions for TBC_KS operation - end                                 //

//////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////

// functions for TBC_TS operation - begin                              //

//////////////////////////////////////////////////////////////////////////////////

void TBC_TS(u8(*TAB)[16], u8* T) {
    u8 TL[8] = { 0, };
    u8 TR[8] = { 0, };
    u8 i = 0;
    u8 r = ROUND_NUM;


    COPY_ARY8(TL, &T[0]);         //TL ← T[0:63];    TR ← T[64:127];
    COPY_ARY8(TR, &T[8]);

    for (i = 0; i<r; i++) {
        if ((i % 3) == 0) {
            ZERO_ARY8(TAB[i]);
        }
        else if ((i % 3) == 1) {
            COPY_ARY8(TAB[i], TL);
        }
        else {
            COPY_ARY8(TAB[i], TR);
        }

    }

}
//////////////////////////////////////////////////////////////////////////////////

// functions for TBC_TS operation - end                                 //

//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
// functions for FO,FE operation - begin                              //
// static case: n1: 32-bit,      n2: 32-bit                              //
//////////////////////////////////////////////////////////////////////////////////
void FOFE(u8* Z, u8* XBTA, u8* RKa, u8* RKb, u8* TB) {
    u8 Y[8] = { 0, };
    u8 i = 0;

    for (i = 0; i<4; i++) {         //Y ← (Xb^Ta)||Tb;
        Y[i] = XBTA[i];
    }

    for (i = 0; i<4; i++) {
        Y[i + 4] = TB[i];
    }

    XOR_ARY8(Y, Y, RKa);         //Y ← Y^RKa;

    //SBL(Y);                  //Y ← SBL(Y);
    //DL(Y);                  //Y ← DL(Y);
    use_box(Y);               // Using LUT instead SBL(). DL()

    XOR_ARY8(Y, Y, RKb);         //Y ← Y^RKb;

    //SBL(Y);                  //Y ← SBL(Y);
    //DL(Y);                  //Y ← DL(Y);
    use_box(Y);               // Using LUT instead SBL(). DL()

    for (i = 0; i<4; i++) {         //Z ← Y[0:(m2?1)];
        Z[i] = Y[i];
    }

}

void FOFE_4(u8* Z, u8* XBTA, u8* RKa, u8* RKb, u8* TB) {
    u8 Y[4] = { 0, };
    u8 i = 0;

    for (i = 0; i<2; i++) {         //Y ← (Xb^Ta)||Tb;
        Y[i] = XBTA[i];
    }

    for (i = 0; i<2; i++) {
        Y[i + 2] = TB[i];
    }

    XOR_ARY4(Y, Y, RKa);         //Y ← Y^RKa;

    //SBL_(Y);                  //Y ← SBL(Y);
    //DL_(Y);                  //Y ← DL(Y);
    use_box_4(Y);               // Using LUT instead SBL(). DL()

    XOR_ARY4(Y, Y, RKb);         //Y ← Y^RKb;

    //SBL_(Y);                  //Y ← SBL(Y);
    //DL_(Y);                  //Y ← DL(Y);
    use_box_4(Y);               // Using LUT instead SBL(). DL()

    for (i = 0; i<2; i++) {         //Z ← Y[0:(m2?1)];
        Z[i] = Y[i];
    }

}

//////////////////////////////////////////////////////////////////////////////////

// functions for F0,FE operation - end                                 //

//////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////

// functions for TBC_ENC operation - begin                              //

//////////////////////////////////////////////////////////////////////////////////

void TBC_ENC(u8* Y, u8* X, u8 (*RKA)[8], u8 (*RKB)[8], u8 (*TAB)[16]) {
    u8 i = 0;
    u8 j = 0;
    u8 r = ROUND_NUM;
    u8 Z[4] = { 0, };
    u8 XA[4] = { 0, };
    u8 XB[4] = { 0, };

    u8 TMP_XA[4] = { 0, };
    u8 TMP_XB[4] = { 0, };

    u8 XBTA[4] = { 0, };

    for (i = 0; i<4; i++) {         //(Xa1, Xb1) ← splitE(X)
        XA[i] = X[i];
        XB[i] = X[4 + i];
    }

    for (i = 0; i<r; i++) {         // for i = 1 to r do

        for (j = 0; j<4; j++) {
            TMP_XA[j] = XB[j];
        }

        for (j = 0; j<4; j++) {
            XBTA[j] = XB[j] ^ TAB[i][j + 4];  // case 2   !!
        }

        FOFE(Z, XBTA, RKA[i], RKB[i], &TAB[i][8]);

        for (j = 0; j<4; j++) {
            TMP_XB[j] = Z[j] ^ XA[j];
        }

        for (j = 0; j<4; j++) {
            XA[j] = TMP_XA[j];
            XB[j] = TMP_XB[j];
        }
    }
    for (i = 0; i<4; i++) {
        Y[4 + i] = XA[i];
        Y[i] = XB[i];
    }
}


void TBC_ENC_4(u8*Y, u8*X, u8(*RKA)[8], u8(*RKB)[8], u8(*TAB)[16]) {
    u8 i = 0;
    u8 j = 0;
    u8 r = ROUND_NUM;
    u8 Z[2] = { 0, };
    u8 XA[2] = { 0, };
    u8 XB[2] = { 0, };

    u8 TMP_XA[2] = { 0, };
    u8 TMP_XB[2] = { 0, };

    u8 XBTA[2] = { 0, };

    for (i = 0; i<2; i++) {         //(Xa1, Xb1) ← splitE(X)
        XA[i] = X[i];
        XB[i] = X[2 + i];
    }

    for (i = 0; i<r; i++) {         // for i = 1 to r do

        for (j = 0; j<2; j++) {
            TMP_XA[j] = XB[j];
        }

        for (j = 0; j<2; j++) {
            XBTA[j] = XB[j] ^ TAB[i][j + 2];  // case 2   !!
        }

        FOFE_4(Z, XBTA, RKA[i], RKB[i], &TAB[i][8]);

        for (j = 0; j<2; j++) {
            TMP_XB[j] = Z[j] ^ XA[j];
        }

        for (j = 0; j<2; j++) {
            XA[j] = TMP_XA[j];
            XB[j] = TMP_XB[j];
        }
    }
    for (i = 0; i<2; i++) {
        Y[2 + i] = XA[i];
        Y[i] = XB[i];
    }
}


//////////////////////////////////////////////////////////////////////////////////

// functions for TBC_ENC operation - end                              //

//////////////////////////////////////////////////////////////////////////////////




//////////////////////////////////////////////////////////////////////////////////

// functions for TBC_DEC operation - begin                              //

//////////////////////////////////////////////////////////////////////////////////

void TBC_DEC(u8* X, u8* Y, u8 (*RKA)[8], u8 (*RKB)[8], u8 (*TAB)[16]) {

    u8 i = 0;
    u8 j = 0;
    u8 r = ROUND_NUM;
    u8 Z[4] = { 0, };
    u8 YA[4] = { 0, };
    u8 YB[4] = { 0, };

    u8 TMP_YA[4] = { 0, };
    u8 TMP_YB[4] = { 0, };

    u8 YBTA[4] = { 0, };

    for (i = 0; i<4; i++) {         //(Ya1, Yb1) ← splitE(Y)
        YA[i] = Y[i];
        YB[i] = Y[4 + i];
    }

    for (i = 18; i>0; i--) {         // for i = 1 to r do

        for (j = 0; j<4; j++) {
            TMP_YA[j] = YB[j];
        }

        for (j = 0; j<4; j++) {
            YBTA[j] = YB[j] ^ TAB[i - 1][j + 4];  // case 2  !!
        }

        FOFE(Z, YBTA, RKA[i - 1], RKB[i - 1], &TAB[i - 1][8]);

        for (j = 0; j<4; j++) {
            TMP_YB[j] = Z[j] ^ YA[j];
        }

        for (j = 0; j<4; j++) {
            YA[j] = TMP_YA[j];
            YB[j] = TMP_YB[j];
        }
    }
    for (i = 0; i<4; i++) {
        X[i + 4] = YA[i];
        X[i] = YB[i];
    }
}

void TBC_DEC_4(u8*X, u8*Y, u8(*RKA)[8], u8(*RKB)[8], u8(*TAB)[16]) {

    u8 i = 0;
    u8 j = 0;
    u8 r = ROUND_NUM;
    u8 Z[2] = { 0, };
    u8 YA[2] = { 0, };
    u8 YB[2] = { 0, };

    u8 TMP_YA[2] = { 0, };
    u8 TMP_YB[2] = { 0, };

    u8 YBTA[2] = { 0, };

    for (i = 0; i<2; i++) {         //(Ya1, Yb1) ← splitE(Y)
        YA[i] = Y[i];
        YB[i] = Y[2 + i];
    }

    for (i = 18; i>0; i--) {         // for i = 1 to r do

        for (j = 0; j<2; j++) {
            TMP_YA[j] = YB[j];
        }

        for (j = 0; j<2; j++) {
            YBTA[j] = YB[j] ^ TAB[i - 1][j + 2];  // case 2  !!
        }

        FOFE_4(Z, YBTA, RKA[i - 1], RKB[i - 1], &TAB[i - 1][8]);

        for (j = 0; j<2; j++) {
            TMP_YB[j] = Z[j] ^ YA[j];
        }

        for (j = 0; j<2; j++) {
            YA[j] = TMP_YA[j];
            YB[j] = TMP_YB[j];
        }
    }
    for (i = 0; i<2; i++) {
        X[i + 2] = YA[i];
        X[i] = YB[i];
    }
}

/////////////////////////////////////////////END - for FEA code adjustment///////////////////////////////////////////////
/////////////////////////////////////////////END - for FEA code adjustment///////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////

// functions for base-64  - start                              //

//////////////////////////////////////////////////////////////////////////////////

static const char MimeBase64[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/'
};

static int DecodeMimeBase64[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

typedef union {
    struct {
        unsigned char c1, c2, c3;
    };
    struct {
        unsigned int e1 : 6, e2 : 6, e3 : 6, e4 : 6;
    };
} BF;

void base64e(u8 *src, char *result, int length) {
    int i, j = 0;
    BF temp;

    for (i = 0; i < length; i = i + 3, j = j + 4) {
        temp.c3 = src[i];
        if ((i + 1) > length) temp.c2 = 0;
        else temp.c2 = src[i + 1];
        if ((i + 2) > length) temp.c1 = 0;
        else temp.c1 = src[i + 2];

        result[j] = MimeBase64[temp.e4];
        result[j + 1] = MimeBase64[temp.e3];
        result[j + 2] = MimeBase64[temp.e2];
        result[j + 3] = MimeBase64[temp.e1];

        if ((i + 2) > length) result[j + 2] = '=';
        if ((i + 3) > length) result[j + 3] = '=';
    }
}

void base64d(char *src, char *result, int *length) {
    int i, j = 0, src_length, blank = 0;
    BF temp;

    src_length = strlen(src);

    for (i = 0; i < src_length; i = i + 4, j = j + 3) {
        temp.e4 = DecodeMimeBase64[src[i]];
        temp.e3 = DecodeMimeBase64[src[i + 1]];
        if (src[i + 2] == '=') {
            temp.e2 = 0;
            blank++;
        }
        else temp.e2 = DecodeMimeBase64[src[i + 2]];
        if (src[i + 3] == '=') {
            temp.e1 = 0;
            blank++;
        }
        else temp.e1 = DecodeMimeBase64[src[i + 3]];

        result[j] = temp.c3;
        result[j + 1] = temp.c2;
        result[j + 2] = temp.c1;
    }
    *length = j - blank;
}



//////////////////////////////////////////////////////////////////////////////////

// functions for base-64  - end                              //

//////////////////////////////////////////////////////////////////////////////////





static void unpack(UINT32 a,MR_BYTE *b)
{ /* unpack bytes from a word */
    b[0]=MR_TOBYTE(a);
    b[1]=MR_TOBYTE(a>>8);
    b[2]=MR_TOBYTE(a>>16);
    b[3]=MR_TOBYTE(a>>24);
}

/* Little Endian */

static int to_base_256(char *x,int len,int s,MR_BYTE *y)
{ /* x[] of length len to base s is converted to byte array y[] of length BLOCK_SIZE */
	int i,j,m;
	UINT32 c;

	for (i=0;i<BLOCK_SIZE;i++) y[i]=0;
	if (len==0) return 0;	

	m=1; y[0]=x[len-1];
	for (j=len-2;j>=0;j--)
	{ /* multiply by s */
		c=x[j];
		for (i=0;i<m;i++)
		{
			c+=(UINT32)y[i]*s;
			y[i]=c&0xff;
			c>>=8;
		}
		if (c>0) {m++; y[m-1]=c;}
	}
	
	return m;
}

/* Find max_b for chosen cipher and number base */

static int maxb(int s)
{
	MR_BYTE y[BLOCK_SIZE];
	int i,m,n,c;
	if (s==2) return 192;
	m=1; y[0]=1;
	for (n=0;;n++)
	{
		c=0;
		for (i=0;i<m;i++)
		{ /* multiply y by s */
			c+=(UINT32)y[i]*s;
			y[i]=c&0xff;
			c>>=8;
		}
		if (c>0) {m++; y[m-1]=c;}
		if (m==13) break;	/* greater than 2^96 for AES */
	}
	return 2*n;
}

static void from_base_256(int addsub,MR_BYTE *y,int len,int s,char *x)
{ /* y[] of length BLOCK_SIZE is added to or subtracted from base s array x[] of length len. */
	int i,m,n;
	UINT32 c,d;

	m=BLOCK_SIZE;
	n=0; c=0;
	forever
	{
		while (m>0 && y[m-1]==0) m--;
		d=0;
		for (i=m-1;i>=0;i--)
		{ /* divide y by s */
			d=(d<<8)+y[i];
			y[i]=d/s;
			d%=s;
		}
		if (addsub==ENCRYPT)
		{ /* ADD */
			d+=c+x[n]; c=0;
			if ((int)d>=s) 
				{c=1; x[n]=d-s;}
			else x[n]=d;
		}
		else
		{ /* SUB */
			d+=c; c=0;
			if ((UINT32)x[n]>=d) x[n]-=d;
			else
				{x[n]+=(s-d); c=1;}
		}
		n++;
		if (n>=len) break;
	}
}

/* AES instance must be initialised and passed */
/* Format Preserving Encryption/Decryption routine */
/* Array x of length len to base s is encrypted/decrypted in place */

static void BC(int crypt,char *x,int len,int s,aes *a,UINT32 TL,UINT32 TR)
{
	int i,j;
	char *left,*right;
	MR_BYTE buff[BLOCK_SIZE];
	int l,r;
	l=r=len/2;
	if (len%2==1) l++;

	left=&x[0]; right=&x[l];

	for (i=0;i<W;i++)
	{
		if (crypt==ENCRYPT) j=i;
		else j=W-i-1;
		if (j%2==0)
		{
			to_base_256(right,r,s,buff);
			unpack(TR^j,&buff[12]);
			aes_ecb_encrypt(a,buff);
			from_base_256(crypt,buff,l,s,left);
		}
		else
		{
			to_base_256(left,l,s,buff);
			unpack(TL^j,&buff[12]);
			aes_ecb_encrypt(a,buff);
			from_base_256(crypt,buff,r,s,right);
		}
	}
}

/* Algorithm 3 */

/* x is an array of length len of numbers to the base s */
/* a is an initialised AES instance  */
/* TL and TR are 32-bit tweak values */
/* x is replaced in place by encrypted values. The format of x[] is preserved */

void FPE_encrypt(int s,aes *a,UINT32 TL,UINT32 TR,char *x,int len)
{
	int i,j,c,rest,mb=maxb(s);
	if (len<=mb)
	{
		BC(ENCRYPT,x,len,s,a,TL,TR);
		return;
	}
	rest=len%mb;
	c=0; i=0;
	while (len-c>=mb)
	{
		if (i!=0) for (j=c;j<c+mb;j++) x[j]=(x[j]+x[j-mb])%s;
		BC(ENCRYPT,&x[c],mb,s,a,TL^(i<<16),TR^(i<<16));
		c+=mb; i++;
	}
	if (len!=c)
	{
		for (j=len-rest;j<len;j++)
			x[j]=(x[j]+x[j-mb])%s;
		BC(ENCRYPT,&x[len-mb],mb,s,a,TL^(i<<16),TR^(i<<16));
	}
}

/* Algorithm 4 */

void FPE_decrypt(int s,aes *a,UINT32 TL,UINT32 TR,char *x,int len)
{
	int i,j,c,rest,mb=maxb(s);
	int b;
	if (len<=mb)
	{
		BC(DECRYPT,x,len,s,a,TL,TR);
		return;
	}
	rest=len%mb;
	c=len-rest; i=c/mb;
	if (len!=c)
	{
		BC(DECRYPT,&x[len-mb],mb,s,a,TL^(i<<16),TR^(i<<16));
		for (j=len-rest;j<len;j++)
			{b=(x[j]-x[j-mb])%s; if (b<0) x[j]=b+s; else x[j]=b;}
	}
	while (c!=0)
	{
		c-=mb; i--;
		BC(DECRYPT,&x[c],mb,s,a,TL^(i<<16),TR^(i<<16));
		if (i!=0) for (j=c;j<c+mb;j++) {b=(x[j]-x[j-mb])%s; if (b<0) x[j]=b+s; else x[j]=b;}
	}
}

/* Test Program - runs NIST test vectors from http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/FF3samples.pdf */

#ifdef FPE_TEST

JNIEXPORT jstring JNICALL
Java_com_example_keyboard_1fpe_MainActivity_encrypt(JNIEnv* env, jobject jobj, jstring jstr, jint n)
{
    int i,j,radix;
    aes a;
    char key[32];
    const char *x = (*env)->GetStringUTFChars(env, jstr, 0);
    unsigned long TL,TR;

//# sample #1

    radix=128;
    TL=0xD8E7920A;
    TR=0xFA330A73; /* random tweaks */

/* Set AES key */
//EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94

    key[15]=0xEF; key[14]=0x43; key[13]=0x59; key[12]=0xD8; key[11]=0xD5; key[10]=0x80; key[9]=0xAA; key[8]=0x4F;
    key[7]=0x7F; key[6]=0x03; key[5]=0x6D; key[4]=0x6F; key[3]=0x04; key[2]=0xFC; key[1]=0x6A; key[0]=0x94;

    aes_init(&a,MR_ECB,16,key,NULL);

    FPE_encrypt(radix,&a,TL,TR,x,n);

    return (*env)->NewStringUTF(env,x);
}

JNIEXPORT jstring JNICALL
Java_com_example_keyboard_1fpe_MainActivity_decrypt(JNIEnv* env, jobject jobj, jstring jstr, jint n)
{
    int i,j,radix;
    aes a;
    char key[32];
    //char x[256] ={0};    /* any length... */
    const char *x = (*env)->GetStringUTFChars(env, jstr, 0);
    unsigned long TL,TR;

//# sample #1

    radix=128;
    TL=0xD8E7920A;
    TR=0xFA330A73; /* random tweaks */

/* Set AES key */
//EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94

    key[15]=0xEF; key[14]=0x43; key[13]=0x59; key[12]=0xD8; key[11]=0xD5; key[10]=0x80; key[9]=0xAA; key[8]=0x4F;
    key[7]=0x7F; key[6]=0x03; key[5]=0x6D; key[4]=0x6F; key[3]=0x04; key[2]=0xFC; key[1]=0x6A; key[0]=0x94;

    aes_init(&a,MR_ECB,16,key,NULL);

	FPE_decrypt(radix,&a,TL,TR,x,n);

    return (*env)->NewStringUTF(env,x);
}

JNIEXPORT jstring JNICALL
Java_com_example_keyboard_1fpe_MainActivity_aesenc(JNIEnv* env, jobject jobj, jstring jstr,jint n)
{
    aes a;
    char key[32];
    const char *x = (*env)->GetStringChars(env, jstr, 0);
    char buff[BLOCK_SIZE]={0,};
    int radix=128;

/* Set AES key */
//EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94

    key[15]=0xEF; key[14]=0x43; key[13]=0x59; key[12]=0xD8; key[11]=0xD5; key[10]=0x80; key[9]=0xAA; key[8]=0x4F;
    key[7]=0x7F; key[6]=0x03; key[5]=0x6D; key[4]=0x6F; key[3]=0x04; key[2]=0xFC; key[1]=0x6A; key[0]=0x94;

    memcpy(buff,x,n);
    aes_init(&a,MR_ECB,16,key,NULL);
    aes_ecb_encrypt(&a,buff);


    return (*env)->NewString(env,buff,16);
}


///////////////var for FEA////////////////


// = { 0, }
// = { { 0, }, }
///////////////var for FEA////////////////


///////////////////////////FEA START//////////////////////////////
///////////////////////////FEA START//////////////////////////////
///////////////////////////FEA START//////////////////////////////
///////////////////////////FEA START//////////////////////////////


int cnt=0;
int cnt_4 = 0;
u8 K[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}; // Test vector for Key
u8 T[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}; // Test vector for Tweak
u8 RKa[18][8] = {{0,},};
u8 RKb[18][8] = {{0,},};
u8 Tab[18][16] = {{0,},};


JNIEXPORT jstring JNICALL
Java_com_example_keyboard_1fpe_MainActivity_tbcenc(JNIEnv* env, jobject jobj, jstring jstr) {
    u8 var[8] = {0,};  // initial Str
    u8 var_mid[8] = {0,}; // mid (encrypt) Str
    u8 n = 64;
    u8 BX[8] = {0,};
    u8 Y[8] = {0,};

//const char *x = (*env)->GetStringUTFChars(env, jstr, 0);
//Initialize secret key, tweak
    u8 N_P = 0;
    u8 N_E = 0;
    u64 Plain = 0;
    u64 E_Plain = 0;
    u64 E_Plain_ = 0;
    // 문자열을 char 배열로
    int i=0;

    char* x = (*env)->GetStringUTFChars(env, jstr, 0);

    cnt = 0;

    for(i=0; i<8; i++){
        var[i] = x[i];
    }

    StrToNum(&Plain, var);
    NumToBits(Plain, BX);

    N_P = (u32)(log10((float)Plain)) + 1;

    //TBC_KS(RKa, RKb, K, n);

    //TBC_TS(Tab, T);
    TBC_ENC(Y, BX, RKa, RKb, Tab);

    BitsToNum(&E_Plain, Y);

    E_Plain_ = E_Plain;
    E_Plain = 0;
    N_E = (u32)(log10((float)E_Plain_)) + 1;

    if (N_E != N_P) {
        while (1) {
            cnt++;
            TBC_ENC(Y, Y, RKa, RKb, Tab);
            BitsToNum(&E_Plain, Y);
            E_Plain_ = E_Plain;
            E_Plain = 0;
            N_E = (u32)(log10((float)E_Plain_)) + 1;

            if (N_E == N_P)
                break;
        }
    }
    NumToStr(&E_Plain_, var_mid);

    //*length = sizeof(var_mid)/ sizeof(u8);
    base64e(var_mid,x,8); //--> test case 1
    //base64d(var_mid,result,length); // --> test case 2


    //return (*env)->NewStringUTF(env,result);  //--> test case 2
    return (*env)->NewStringUTF(env,x);  //--> test case 1
    //return (*env)->NewStringUTF(env,var_mid); --> basic
}

JNIEXPORT jstring JNICALL
Java_com_example_keyboard_1fpe_MainActivity_tbcdec(JNIEnv* env, jobject jobj, jstring jstr, jint n) {
    int i=0;
    u8 var_after[8] = { 0, };  // after Str

    u8 Y[8] = { 0, };
    u8 Dec[8] = { 0, };
    u64 D_Plain = 0;

    char *x = (*env)->GetStringUTFChars(env, jstr, 0);


    int c_n = n; // 암호문 인코딩 후의 문자열 길이  --> x의 길이
    base64d(x, Y, &c_n);

    TBC_DEC(Dec, Y, RKa, RKb, Tab);
    if (cnt>0) {
        for (i = 0; i<cnt; i++) {
            TBC_DEC(Dec, Dec, RKa, RKb, Tab);
        }
    }

    BitsToNum(&D_Plain, Dec);
    NumToStr(&D_Plain, var_after);
/*
    for(i=0; i<8; i++){
        dec_new[i] = var_after[i];
    }
*/
    for(i=0; i<8; i++){
        x[i] = var_after[i];
    }
    return (*env)->NewStringUTF(env,x);
}

JNIEXPORT jstring JNICALL
Java_com_example_keyboard_1fpe_MainActivity_tbcenc4(JNIEnv* env, jobject jobj, jstring jstr) {
    u8 var[4] = {0,};  // initial Str
    u8 var_mid[4] = {0,}; // mid (encrypt) Str

    u8 n = 64;
    u8 BX[4] = {0,};

    u8 Y[4] = {0,};


//const char *x = (*env)->GetStringUTFChars(env, jstr, 0);
//Initialize secret key, tweak
    u8 N_P = 0;
    u8 N_E = 0;
    u64 Plain = 0;
    u64 E_Plain = 0;
    u64 E_Plain_ = 0;
    // 문자열을 char 배열로
    int i=0;

    char* x = (*env)->GetStringUTFChars(env, jstr, 0);


    cnt_4 = 0;


    for(i=0; i<4; i++){
        var[i] = x[i];
    }

    StrToNum_4(&Plain, var);
    NumToBits_4(Plain, BX);

    N_P = (u32)(log10((float)Plain)) + 1;

    //TBC_KS(RKa, RKb, K, n);

    //TBC_TS(Tab, T);
    TBC_ENC_4(Y, BX, RKa, RKb, Tab);

    BitsToNum_4(&E_Plain, Y);

    E_Plain_ = E_Plain;
    E_Plain = 0;
    N_E = (u32)(log10((float)E_Plain_)) + 1;

    if (N_E != N_P) {
        while (1) {
            cnt_4++;
            TBC_ENC_4(Y, Y, RKa, RKb, Tab);
            BitsToNum_4(&E_Plain, Y);
            E_Plain_ = E_Plain;
            E_Plain = 0;
            N_E = (u32)(log10((float)E_Plain_)) + 1;

            if (N_E == N_P)
                break;
        }
    }
    NumToStr_4(&E_Plain_, var_mid);

    //*length = sizeof(var_mid)/ sizeof(u8);
    base64e(var_mid,x,4); //--> test case 1
    //base64d(var_mid,result,length); // --> test case 2


    //return (*env)->NewStringUTF(env,result);  //--> test case 2
    return (*env)->NewStringUTF(env,x);  //--> test case 1
    //return (*env)->NewStringUTF(env,var_mid); --> basic
}

JNIEXPORT jstring JNICALL
Java_com_example_keyboard_1fpe_MainActivity_tbcdec4(JNIEnv* env, jobject jobj, jstring jstr, jint n) {
    int i=0;
    char dec_new[4] = {0,};
    u8 var_after[4] = { 0, };  // after Str

    u8 Y[4] = { 0, };
    u8 Dec[4] = { 0, };
    u64 D_Plain = 0;

    char *x = (*env)->GetStringUTFChars(env, jstr, 0);


    int c_n = n; // 암호문 인코딩 후의 문자열 길이  --> x의 길이
    base64d(x, Y, &c_n);

    TBC_DEC_4(Dec, Y, RKa, RKb, Tab);
    if (cnt_4>0) {
        for (i = 0; i<cnt_4; i++) {
            TBC_DEC_4(Dec, Dec, RKa, RKb, Tab);
        }
    }

    BitsToNum_4(&D_Plain, Dec);
    NumToStr_4(&D_Plain, var_after);

    for(i=0; i<4; i++){
        x[i] = var_after[i];
    }

    //return (*env)->NewStringUTF(env,var_after);
    //return (*env)->NewStringUTF(env,dec_new);
    return (*env)->NewStringUTF(env,x);
}
JNIEXPORT jstring JNICALL
Java_com_example_keyboard_1fpe_MainActivity_KSTS(JNIEnv* env, jobject jobj, jstring jstr) {
    u8 n=64;
    char *x = (*env)->GetStringUTFChars(env, jstr, 0);
    TBC_KS(RKa, RKb, K, n);

    TBC_TS(Tab, T);
    return (*env)->NewStringUTF(env,x);
}

#endif
