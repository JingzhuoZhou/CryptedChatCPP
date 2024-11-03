#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "sha256.h"

#define SHA_BLOCK_LENGTH_BITS 512
#define SHA_BLOCK_LENGTH_BYTES 64
#define SHA_NUM_STEPS 64
#define SHA_NUM_WORDS_IN_BLOCK 16
#define SHA_DIGEST_LENGTH_BYTES 32
const int ML=32,MAXLEN=2000000;

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

unsigned char pltxt[MAXLEN],ctxt[ML];
inline uint32_t rrot(uint32_t x,int num){
    return (x<<(32-num))|(x>>num);
}
uint8_t* sha_256(const uint8_t *message, const uint64_t& m_len_bytes) {
    uint8_t *digest = new uint8_t[SHA_DIGEST_LENGTH_BYTES];
    /* Your code here */
    uint32_t H[8]={
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    // padding
    int padding = (448-1+512-m_len_bytes * 8 % 512)%512 / 8+1;
    size_t new_len = m_len_bytes + padding + 8;
    uint8_t *buf=new uint8_t[new_len];
    memcpy(buf, message, m_len_bytes);
    for(int i=m_len_bytes;i<m_len_bytes+padding;++i)buf[i]=0;
    
    buf[m_len_bytes] = (uint8_t)0x80;
    for (int i = 0; i < 8; i++)
        buf[new_len-8+i] = ((m_len_bytes<<3) >> (8*(7 - i))) & 0xff;// 填充长度
        
    uint32_t w[64],a[8],val,s0,s1,ch,maj,t1,t2;
    size_t chunk_len = new_len / 64;
    
    for (int id = 0; id < chunk_len; id++) {
        for (int i = 0; i < 16; i++) {// 0-15
            val=0;
            for (int j=0;j<4;++j)val=val|(buf[id*64+i*4+j] << (8*(3-j)));
            w[i] = val;
        }
        for (int i = 16; i < 64; i++) {// 16-63
            s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >> 3);
            s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            
        }
       
        for(int i=0;i<8;++i)a[i]=H[i];
        for (int i = 0; i < 64; i++) {// 64轮
            s0 = rrot(a[0], 2) ^ rrot(a[0], 13) ^ rrot(a[0], 22);
            s1 = rrot(a[4], 6) ^ rrot(a[4], 11) ^ rrot(a[4], 25);
            ch = (a[4] & a[5]) ^ (~a[4] & a[6]);
            maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
            t1 = a[7] + s1 + ch + k[i] + w[i];
            t2 = s0 + maj;
            for(int j=7;j>0;--j)a[j]=a[j-1];
            a[4]+=t1;
            a[0]=t1+t2;
        }
        for(int i=0;i<8;++i)H[i]+=a[i];
        
    }
    delete[] buf;
    for(int i=0;i<8;++i)
        for(int j=0;j<4;++j)digest[i*4+j]=(H[i]>>8*(3-j))&0xff;
    return digest;
}

bool SHA_check_vector() {
    const uint8_t *message = (const uint8_t*)"abc";
    uint8_t *digest = sha_256(message, 24);
    uint8_t goal_digest[SHA_DIGEST_LENGTH_BYTES] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    for (int i = 0; i < SHA_DIGEST_LENGTH_BYTES; i++) {
        if (digest[i] != goal_digest[i]) {
            printf("SHA-256 testvector1 not verified!\n");
            delete[] digest;
            return false;
        }
    }
    printf("SHA-256 testvector1 verified!\n");
    delete[] digest;
    message = (const uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    digest = sha_256(message, 56 * 8);
    uint8_t goal_digest2[SHA_DIGEST_LENGTH_BYTES] = {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1};
    for (int i = 0; i < SHA_DIGEST_LENGTH_BYTES; i++) {
        if (digest[i] != goal_digest2[i]) {
            printf("SHA-256 testvector2 not verified!\n");
            delete[] digest;
            return false;
        }
    }
    printf("SHA-256 testvector2 verified!\n");
    delete[] digest;
    return true;
}