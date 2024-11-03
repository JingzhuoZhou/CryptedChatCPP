#include "hmac.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#define min(a,b) ((a)<(b)?(a):(b))
/* return prk */
static uint8_t* HKDF_Extract(const uint8_t *salt, const size_t& salt_len_bytes, const uint8_t *IKM, const size_t& IKM_len_bytes) {
    /* Your code here */
    return hmac_sha256(salt, salt_len_bytes, IKM, IKM_len_bytes);
}

/* return: array of L bytes */
static uint8_t* HKDF_Expand(const uint8_t *prk, const size_t& prk_len_bytes, const uint8_t *info, const size_t& info_len_bytes, const size_t& L_bytes) {
    /* Your code here */
    uint8_t *OKM=new uint8_t[L_bytes];
    uint8_t *T=new uint8_t[32+info_len_bytes+1]; 
    uint8_t *temp;
    int l=0;
    while(l<L_bytes){
        if(l==0){
            memcpy(T,info,info_len_bytes);
            T[info_len_bytes]=1;
            temp=hmac_sha256(prk,prk_len_bytes,T,info_len_bytes+1);
            
        }
        else{
            memcpy(T+32,info,info_len_bytes);
            T[info_len_bytes+32]=uint8_t((l>>5)+1);
            temp=hmac_sha256(prk,prk_len_bytes,T,32+info_len_bytes+1);
        }
        memcpy(T,temp,32);
        memcpy(OKM+l,temp,min(32,L_bytes-l));
        delete[] temp;
        l+=32;
    }
    delete[] T;
    return OKM;
}

/*
    Return: pointer to okm
*/
uint8_t *HKDF(const uint8_t *salt, const size_t& salt_len_bytes, const uint8_t *IKM, const size_t& IKM_len_bytes, const uint8_t *info, const size_t& info_len_bytes, const size_t& L_bytes) {
    /* Your code here */
    uint8_t *PRK = HKDF_Extract(salt, salt_len_bytes, IKM, IKM_len_bytes);
    uint8_t *OKM = HKDF_Expand(PRK, 32, info, info_len_bytes, L_bytes);
    delete[] PRK;
    return OKM;
}
