#include <iostream>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "aes-gcm.h"
#include "aes.h"
using namespace std;
const uint8_t R[16]={0xe1,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
uint8_t H[16];


void multiply(uint8_t* x,uint8_t* y, uint8_t* z){
    uint8_t* v=new uint8_t[16];
    memset(z,0,16);
    memcpy(v,y,16);
    for(int i=0;i<128;++i){
        if(x[i/8]&(1<<(7-i%8))){
            for(int j=0;j<16;++j){
                z[j]^=v[j];
            }
        }
        if(!(v[15]&1)){
            v[15]>>=1;
            for(int j=14;j>=0;--j){
                v[j+1]|=(v[j]&1)<<7;
                v[j]>>=1;
            }
        }
        else{
            v[15]>>=1;
            for(int j=14;j>=0;--j){
                v[j+1]|=(v[j]&1)<<7;
                // v[j+1]^=R[j+1];
                v[j]>>=1;
            }
            v[0]^=R[0];
        }
    }
    delete[] v;
    return;
}
void GHash(uint8_t *x,uint8_t* y,uint64_t len){
    memset(y,0,16);
    uint8_t z[16];
    int m=len/128;
    for(int i=0;i<m;++i){
        Xor(y,x+i*16);
        multiply(H,y,z);
        memcpy(y,z,16);
    }
    return;
}

void addCounter(uint8_t ctr[]){
    //计数器+1
    for(int i=15;i>=12;--i){
        if(ctr[i]!=255){
            ctr[i]++;
            break;
        }
        ctr[i]=0;
    }
}
void GCTR(const uint8_t *x,uint8_t *y,uint8_t *ICB,uint64_t len,const uint8_t *key){
    if(len==0){
        return;
    }
    int n=(len+127)/128;
    uint8_t ctr[16],cipher[16];
    memcpy(ctr,ICB,16);
    for(int i=0;i<n-1;++i){
        aes(ctr,16,key,cipher);
        Xor(cipher,x+i*16);
        memcpy(y+i*16,cipher,16);
        addCounter(ctr);
    }
    aes(ctr,16,key,cipher);
    
    for(int i=(n-1)*16;i<len/8;++i)
        y[i]=cipher[i-(n-1)*16]^x[i];
}
/*
AES_GCM 认证加密函数
plaintext: 明文字节数组. plain_len_bits: 明文比特数.
IV: 初始向量96比特.
AD: 附加认证信息字节数组. AD_len_bits: AD比特数.
key: 128比特密钥
output_ciphertext: 输出密文数组指针地址，长度同密文 output_tag: 输出tag数组指针地址.
ciphertext长度同plaintext, tag长度为128比特(16字节).
*/
void AES_Authenticated_Encryption_GCM(const uint8_t *plaintext, const uint64_t& plain_len_bits, const uint8_t IV[12], const uint8_t *AD, const uint64_t& AD_len_bits, const uint8_t key[16], uint8_t** output_ciphertext, uint8_t** output_tag) {
    /* Your code here */
    uint8_t tmp[16],J[16],J0[16];
    memset(H,0,16);
    aes(H,16,key,tmp);
    memcpy(H,tmp,16);
    
    memcpy(J,IV,12);
    J[12]=J[13]=J[14]=0;
    J[15]=2;
    memcpy(J0,IV,12);
    J0[12]=J0[13]=J0[14]=0;
    J0[15]=1;

    uint8_t *ciphertext=new uint8_t[plain_len_bits>>3];
    GCTR(plaintext,ciphertext,J,plain_len_bits,key);
    *output_ciphertext=ciphertext;

    uint64_t u=(128-plain_len_bits%128)%128,v=(128-AD_len_bits%128)%128;
    uint64_t new_len=((u+v+AD_len_bits+plain_len_bits)>>3)+16;

    uint8_t *linked=new uint8_t[new_len];
    
    memcpy(linked,AD,AD_len_bits>>3);
    memset(linked+(AD_len_bits>>3),0,v>>3);
    memcpy(linked+(AD_len_bits>>3)+(v>>3),ciphertext,plain_len_bits>>3);
    memset(linked+(AD_len_bits>>3)+(v>>3)+(plain_len_bits>>3),0,u>>3);
    for (int i = 0; i < 8; i++)
        linked[new_len-16+i] = ((AD_len_bits) >> (8*(7 - i))) & 0xff;
    for (int i = 0; i < 8; i++)
        linked[new_len-8+i] = ((plain_len_bits) >> (8*(7 - i))) & 0xff;
    
    
    uint8_t *s=new uint8_t[16];
    GHash(linked,s,new_len*8);

    
    uint8_t *c=new uint8_t[new_len];
    GCTR(s,c,J0,128,key);
    uint8_t *tag=new uint8_t[16];
    memcpy(tag,c,16);
    *output_tag=tag;
    delete[] linked;
    delete[] s;
    delete[] c;

}

/*
AES_GCM 认证解密
ciphertext：密文字节数组 cipher_len_bits：密文比特数
IV: 初始向量96比特.
AD: 附加认证信息字节数组. AD_len_bits: AD比特数.
key: 128比特密钥
output_plaintext：明文数组，认证成功，长度同密文。如果认证失败，长度为0
Return value: true if authentication success, false if fail
*/
bool AES_Authenticated_Decryption_GCM(const uint8_t *ciphertext, const uint64_t& cipher_len_bits, const uint8_t IV[12], const uint8_t *AD, const uint64_t& AD_len_bits, const uint8_t key[16], uint8_t** output_plaintext, uint8_t* input_tag) {
    if(AD_len_bits%8!=0)return false;
    uint8_t tmp[16],J[16],J0[16];
    memset(H,0,16);
    aes(H,16,key,tmp);
    memcpy(H,tmp,16);
    
    memcpy(J,IV,12);
    J[12]=J[13]=J[14]=0;
    J[15]=2;
    memcpy(J0,IV,12);
    J0[12]=J0[13]=J0[14]=0;
    J0[15]=1;

    uint8_t *plaintext=new uint8_t[cipher_len_bits/8];
    GCTR(ciphertext,plaintext,J,cipher_len_bits,key);
    
    uint64_t u=(128-cipher_len_bits%128)%128,v=(128-AD_len_bits%128)%128;
    uint64_t new_len=((u+v+AD_len_bits+cipher_len_bits)>>3)+16;

    uint8_t *linked=new uint8_t[new_len];
    
    memcpy(linked,AD,AD_len_bits>>3);
    memset(linked+(AD_len_bits>>3),0,v>>3);
    memcpy(linked+(AD_len_bits>>3)+(v>>3),ciphertext,cipher_len_bits>>3);
    memset(linked+(AD_len_bits>>3)+(v>>3)+(cipher_len_bits>>3),0,u>>3);
    for (int i = 0; i < 8; i++)
        linked[new_len-16+i] = ((AD_len_bits) >> (8*(7 - i))) & 0xff;
    for (int i = 0; i < 8; i++)
        linked[new_len-8+i] = ((cipher_len_bits) >> (8*(7 - i))) & 0xff;
    
    
    uint8_t *s=new uint8_t[16];
    GHash(linked,s,new_len*8);

    
    uint8_t *c=new uint8_t[new_len];
    GCTR(s,c,J0,128,key);
    for(int i=0;i<16;++i)if(c[i]!=input_tag[i]){
        delete[] linked;
        delete[] s;
        delete[] c;
        delete[] plaintext;
        uint8_t *empty=new uint8_t[0];
        *output_plaintext=empty;
        return false;
    }
    *output_plaintext=plaintext;
 
    delete[] linked;
    delete[] s;
    delete[] c;
    return true;
}
