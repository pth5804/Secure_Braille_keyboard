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

//type definition - end                                             //

//////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////

//variable declaration   - begin                                       //

//////////////////////////////////////////////////////////////////////////////////

u8 sbox[16][16] = {

        0x62, 0x31, 0x70, 0x8e, 0xbc, 0x30, 0x9c, 0x78, 0xe0, 0x5c, 0xce, 0xbb, 0x42, 0xac, 0xb8, 0xdf,

        0x29, 0xe7, 0x86, 0x5f, 0xee, 0xba, 0x3f, 0x87, 0xc0, 0x36, 0xc3, 0x14, 0x7c, 0xec, 0x73, 0xda,

        0x57, 0x72, 0xf6, 0x77, 0x98, 0x3b, 0xc5, 0xc4, 0x4c, 0x52, 0x81, 0x20, 0x15, 0x97, 0x26, 0xfc,

        0x8b, 0x3c, 0xaf, 0x6e, 0xc8, 0x7e, 0xf0, 0x40, 0x24, 0xa1, 0xb1, 0x54, 0xff, 0xad, 0x51, 0xbd,

        0xc1, 0x13, 0x41, 0xb5, 0x6b, 0x94, 0x63, 0xd6, 0xde, 0x6f, 0x89, 0xd2, 0xa9, 0xd4, 0x17, 0x38,

        0xa5, 0xf2, 0xe3, 0xdb, 0x47, 0x66, 0xed, 0xcb, 0x4e, 0xd5, 0x05, 0x60, 0x8c, 0x06, 0x92, 0xa3,

        0xbe, 0x68, 0x56, 0xa7, 0x80, 0x32, 0xfa, 0x6c, 0x8f, 0x88, 0xd9, 0x50, 0x0a, 0x21, 0x3d, 0x75,

        0x71, 0x01, 0xe5, 0x7a, 0xc6, 0xb9, 0x82, 0x64, 0xd1, 0x00, 0x7d, 0x2b, 0xa0, 0x1a, 0x5e, 0xf5,

        0x35, 0x90, 0x2f, 0x2a, 0x83, 0x49, 0x5a, 0xa8, 0xd8, 0x8d, 0x46, 0x96, 0xdc, 0xb0, 0xc9, 0xdd,

        0xcd, 0x65, 0x44, 0xc7, 0x43, 0x67, 0x55, 0xeb, 0xe1, 0x9d, 0x34, 0x74, 0xb3, 0x4a, 0xca, 0xd7,

        0x79, 0xbf, 0xf7, 0x99, 0x6a, 0x2d, 0xef, 0x85, 0xe2, 0x5d, 0xfe, 0x11, 0x0f, 0x19, 0xcc, 0xe4,

        0x58, 0x09, 0x8a, 0x1b, 0x6d, 0x91, 0x9f, 0x4b, 0x61, 0x2c, 0x2e, 0xcf, 0x27, 0x10, 0x18, 0xb7,

        0x1d, 0x0c, 0x9b, 0x39, 0x7f, 0xd3, 0x84, 0xa4, 0xf9, 0x76, 0x33, 0xf4, 0xf3, 0xd0, 0x07, 0x0e,

        0x22, 0x1f, 0xfd, 0x25, 0x12, 0x08, 0x1e, 0x4d, 0xb6, 0xb4, 0x53, 0x37, 0xe8, 0xb2, 0x9e, 0x93,

        0x02, 0xe9, 0xf1, 0x3a, 0x0b, 0xfb, 0x45, 0x69, 0xea, 0xf8, 0xc2, 0x1c, 0x04, 0x59, 0x03, 0x48,

        0x16, 0xa2, 0x4f, 0x3e, 0x9a, 0x23, 0xaa, 0xae, 0x5b, 0xe6, 0x95, 0xab, 0x7b, 0x0d, 0x28, 0xa6

};

/*

//type1

u8 RC1_128[6][8] ={

0x7D,0x2E,0xEF,0x8E,0xBD,0x6F,0x36,0x71,

0x3F,0xD1,0x85,0x8A,0x20,0xFF,0x63,0x90,

0x08,0xCB,0x86,0x9A,0x3C,0x4B,0xB5,0xFD,

0xE0,0x4D,0x5E,0xE5,0x2B,0x77,0xEA,0xF2,

0x0B,0x8D,0x9F,0x5B,0xF9,0x14,0x88,0x7C,

0xF5,0x8D,0xBB,0xCC,0xFF,0xFB,0x21,0xEB

};

*/

//type2
/*
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
*/
//////////////////////////////////////////////////////////////////////////////////

//variable declaration   - end                                       //

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

void COPY_ARY4(u8* out, u8* in) {
    int i = 0;

    for (i = 0; i<4; i++) {
        out[i] = in[i];
    }
}

void ZERO_ARY8(u8* inout) {
    int i = 0;
    for (i = 0; i<8; i++) {
        inout[i] = 0;
    }
}

void ZERO_ARY4(u8* inout) {
    int i = 0;
    for (i = 0; i<4; i++) {
        inout[i] = 0;
    }
}


//////////////////////////////////////////////////////////////////////////////////

// functions for generic operation - begin                              //

//////////////////////////////////////////////////////////////////////////////////



//////////////////////////////////////////////////////////////////////////////////

// functions for SBL operation - begin                                 //

//////////////////////////////////////////////////////////////////////////////////

void SBL(u8* X) {

    int i = 0;
    u8 low, high;

    for (i = 0; i < 8; i++) {
        low = X[i] & 0xf;
        high = (X[i] >> 4) & 0xf;
        X[i] = sbox[high][low];
    }

}

void SBL_(u8* X) {
    int i = 0;
    u8 low, high;

    for (i = 0; i < 4; i++) {
        low = X[i] & 0xf;
        high = (X[i] >> 4) & 0xf;
        X[i] = sbox[high][low];
    }
}

//////////////////////////////////////////////////////////////////////////////////

// functions for SBL operation - end                                 //

//////////////////////////////////////////////////////////////////////////////////




//////////////////////////////////////////////////////////////////////////////////

// functions for DL operation - begin                                 //

//////////////////////////////////////////////////////////////////////////////////

u32 Binary_MUL(u8 in1, u8 in2) {
    int i = 0;
    u32 result = 0;

    for (i = 0; i<8; i++) {
        if (in1 & (1 << i)) {
            result ^= (in2 << i);
        }
    }
    return result;
}

u32 Binary_MUL_(u8 in1, u8 in2) {
    int i = 0;
    u32 result = 0;

    for (i = 0; i<4; i++) {
        if (in1 & (1 << i)) {
            result ^= (in2 << i);
        }
    }
    return result;
}


u8 GF28(u8 in1, u8 in2) {
    int i = 0;
    u32 tmp = 0;
    u32 flag = 0x8000;

    tmp = Binary_MUL(in1, in2);

    for (i = 0; i<8; i++) {

        if (flag & tmp) {
            tmp ^= 0x3880;

        }
    }

    return (u8)tmp;
}

u8 GF28_(u8 in1, u8 in2) {

    int i = 0;
    u32 tmp = 0;
    u32 flag = 0x8000;

    tmp = Binary_MUL_(in1, in2);

    for (i = 0; i<8; i++) {

        if (flag & tmp) {
            tmp ^= 0x3880;

        }
    }

    return (u8)tmp;
}

void DL(u8* in1) {
    u8 M[8][8] = {
            0x28, 0x1A, 0x7B, 0x78, 0xC3, 0xD0, 0x42, 0x40,

            0x1A, 0x7B, 0x78, 0xC3, 0xD0, 0x42, 0x40, 0x28,

            0x7B, 0x78, 0xC3, 0xD0, 0x42, 0x40, 0x28, 0x1A,

            0x78, 0xC3, 0xD0, 0x42, 0x40, 0x28, 0x1A, 0x7B,

            0xC3, 0xD0, 0x42, 0x40, 0x28, 0x1A, 0x7B, 0x78,

            0xD0, 0x42, 0x40, 0x28, 0x1A, 0x7B, 0x78, 0xC3,

            0x42, 0x40, 0x28, 0x1A, 0x7B, 0x78, 0xC3, 0xD0,

            0x40, 0x28, 0x1A, 0x7B, 0x78, 0xC3, 0xD0, 0x42
    };

    u8 in2[8] = { 0, };

    int i = 0, j = 0;

    for (i = 0; i<8; i++) {
        in2[i] = in1[i];
        in1[i] = 0;
    }

    for (i = 0; i<8; i++) {
        for (j = 0; j<8; j++) {
            in1[i] ^= GF28(in2[j], M[i][j]);  // Original   //Choose one of these
            //in1[i] = in1[i] ^ ((in2[j] * M[i][j])% GF);  //Choose one of these
        }
    }

}

void DL_(u8* in1) {
    u8 M[8][8] = {
            0x28, 0x1A, 0x7B, 0x78, 0xC3, 0xD0, 0x42, 0x40,

            0x1A, 0x7B, 0x78, 0xC3, 0xD0, 0x42, 0x40, 0x28,

            0x7B, 0x78, 0xC3, 0xD0, 0x42, 0x40, 0x28, 0x1A,

            0x78, 0xC3, 0xD0, 0x42, 0x40, 0x28, 0x1A, 0x7B,

            0xC3, 0xD0, 0x42, 0x40, 0x28, 0x1A, 0x7B, 0x78,

            0xD0, 0x42, 0x40, 0x28, 0x1A, 0x7B, 0x78, 0xC3,

            0x42, 0x40, 0x28, 0x1A, 0x7B, 0x78, 0xC3, 0xD0,

            0x40, 0x28, 0x1A, 0x7B, 0x78, 0xC3, 0xD0, 0x42
    };

    u8 in2[4] = { 0, };

    int i = 0, j = 0;

    for (i = 0; i<4; i++) {
        in2[i] = in1[i];
        in1[i] = 0;
    }

    for (i = 0; i<4; i++) {
        for (j = 0; j<4; j++) {
            in1[i] ^= GF28_(in2[j], M[i][j]);  // Original   //Choose one of these
            //in1[i] = in1[i] ^ ((in2[j] * M[i][j])% GF);  //Choose one of these
        }
    }

}



//////////////////////////////////////////////////////////////////////////////////

// functions for DL operation - end                                    //

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

        SBL(X);                  //X ← SBL(X);
        DL(X);                  //X ← DL(X);

        XOR_ARY8(Y, KB, KD);         //Y ← Kb^Kd^n^X;
        Y[0] = Y[0] ^ n;
        XOR_ARY8(Y, Y, X);

        SBL(Y);                  //Y ← SBL(Y);
        DL(Y);                  //Y ← DL(Y);

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
    u8 j = 0;
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

    SBL(Y);                  //Y ← SBL(Y);


    DL(Y);                  //Y ← DL(Y);


    XOR_ARY8(Y, Y, RKb);         //Y ← Y^RKb;

    SBL(Y);                  //Y ← SBL(Y);

    DL(Y);                  //Y ← DL(Y);

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

    SBL_(Y);                  //Y ← SBL(Y);


    DL_(Y);                  //Y ← DL(Y);


    XOR_ARY4(Y, Y, RKb);         //Y ← Y^RKb;

    SBL_(Y);                  //Y ← SBL(Y);

    DL_(Y);                  //Y ← DL(Y);

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
/////////////////////////////////////////////END - for FEA code adjustment///////////////////////////////////////////////
/////////////////////////////////////////////END - for FEA code adjustment///////////////////////////////////////////////
/////////////////////////////////////////////END - for FEA code adjustment///////////////////////////////////////////////
/////////////////////////////////////////////END - for FEA code adjustment///////////////////////////////////////////////
/////////////////////////////////////////////END - for FEA code adjustment///////////////////////////////////////////////
/////////////////////////////////////////////END - for FEA code adjustment///////////////////////////////////////////////
/////////////////////////////////////////////END - for FEA code adjustment///////////////////////////////////////////////
/////////////////////////////////////////////END - for FEA code adjustment///////////////////////////////////////////////
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
