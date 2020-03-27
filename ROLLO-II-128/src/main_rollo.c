
#include <stdio.h>
#include <stdlib.h>
#include "api.h"
#include "string.h"
#include "parameters.h"
#include <time.h>
#include "hash.h"
//#include "crypto_hash.h"
#include "nist-rng.h"
#include <sys/syscall.h>

long long cpucycles() {
  unsigned long long result;
  __asm__ volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax" : "=a" (result) ::  "%rdx");
  return result;
}

int Registration(unsigned char *Deviceid, unsigned char *Spk, unsigned *Ssk, unsigned char *Dpk, unsigned char* Dsk);
int Authentication(unsigned char *Deviceid, unsigned char *sk, unsigned char *pk, unsigned char *ss1, unsigned char *ss2);

int main() {
  printf("\n");
  printf("*******************\n");
  printf("**** ROLLO-%d ****\n", PARAM_SECURITY);
  printf("*******************\n");

  
  unsigned char Deviceid[2] = {0xab,0xcd};
  unsigned char Etime[8];
    
  unsigned char Spk[PUBLIC_KEY_BYTES];
  unsigned char Ssk[SECRET_KEY_BYTES];
  unsigned char Dpk[PUBLIC_KEY_BYTES];
  unsigned char Dsk[SECRET_KEY_BYTES];
  unsigned char ct[CIPHERTEXT_BYTES];
  unsigned char ss1[HASH_LEN];
  unsigned char ss2[HASH_LEN];
  
  unsigned char seed[48];
  int result;
    
  syscall(318, seed, 48, 0);
  randombytes_init(seed, NULL, 256);
    
  clock_t t1 = clock();
  crypto_kem_keypair(Spk, Ssk);
  crypto_kem_keypair(Dpk, Dsk);
  clock_t t2 = clock();

  result = Registration(Deviceid, Spk, Ssk, Dpk, Dsk);
  printf("Registration Result : %d (1:Succeed, 0:Failed)\n", result);
  result = Authentication(Deviceid, Ssk, Spk, ss1, ss2);
  printf("Authentication Result : %d (1:Succeed, 0:Failed)\n", result);
    printf("ss1 = ");
    for(int i=0; i<HASH_LEN; i++){
        printf("%x",ss1[i]);
    }
    printf("\nss2 = ");
    for(int i=0; i<HASH_LEN; i++){
        printf("%x",ss2[i]);
    }
    printf("\n");
}

// Device Registration
int Registration(unsigned char *Deviceid, unsigned char *Spk, unsigned *Ssk, unsigned char *Dpk, unsigned char* Dsk){
    unsigned char NonceA[2] = {0x12,0x34}; //Nonce should generate randomly
    unsigned char Input[4] = {Deviceid[0],Deviceid[1],NonceA[0],NonceA[1]};
    unsigned char Message[4];
    unsigned char Message2[4];
    unsigned char Req[CIPHERTEXT_BYTES];
    unsigned char c1[CIPHERTEXT_BYTES];
    unsigned char PW[2];
    unsigned char hashinput[2];
    unsigned char P1[HASH_LEN];
    unsigned char VP1[HASH_LEN];
    
    printf("**** Registration Start ****\n");
    
    crypto_kem_enc(Req, Input, Spk);
    
    printf("**** Send Request Message ****\n");
    
    //Decrypt Request Message
    crypto_kem_dec(Message, Req, Ssk);
    
    //Generate Password
    PW[0] =0xab;
    PW[1] =0xcd;
    
    //Compute c1
    Input[0] = PW[0];
    Input[1] = PW[1];
    Input[2] = Message[2];
    Input[3] = Message[3];
    crypto_kem_enc(c1, Input, Dpk);
    
    printf("**** Send c1 ****\n");
    
    //Decrypt c1
    crypto_kem_dec(Message2, c1, Dsk);
    
    //Verify Nonce
    for(int i=2; i<4; i++){
        if(Message2[i] != NonceA[i-2]){
            printf("Verify c1 Failed");
            return 0;
        }
    }
    
    //Compute P1
    hashinput[0] =  NonceA[0] ^ Message2[0];
    hashinput[1] =  NonceA[1] ^ Message2[1];
    sha512(P1, hashinput, 2);
    
    printf("**** Send P1 ****\n");
    
    //Verify P1
    hashinput[0] = PW[0] ^ Message[2];
    hashinput[1] = PW[1] ^ Message[3];
    sha512(VP1, hashinput, 2);
    
    if(memcmp(P1,VP1,HASH_LEN) == 0)
           printf("Verify P1 Succeed\n");
    else{
        printf("Verify P1 Failed");
        return 0;
    }
    
    return 1;
}

int Authentication(unsigned char *Deviceid, unsigned char *sk, unsigned char *pk, unsigned char *ss1, unsigned char *ss2){
    unsigned char NonceB[2] = {0xff, 0xee};
    unsigned char Input[4] = {Deviceid[0],Deviceid[1],NonceB[0],NonceB[1]};
    unsigned char c2[CIPHERTEXT_BYTES];
    unsigned char P2[64];
    unsigned char Message[4];
    unsigned char DevicePW[2] = {0xab,0xcd};
    unsigned char ServerPW[2] = {0xab,0xcd};
    unsigned char hashinput4[4];
    unsigned char hashinput2[2];
    unsigned char PWtemp[2];
    unsigned char VP2[HASH_LEN];
    unsigned char P3[HASH_LEN];
    unsigned char VP3[HASH_LEN];
    unsigned char P4[HASH_LEN];
    unsigned char VP4[HASH_LEN];
    
    printf("\n**** Authentication Start ****\n");

    //Encrypt DeviceId, Nonce
    crypto_kem_enc(c2, Input, pk);
    
    //Compute P2
    hashinput4[0] = DevicePW[0];
    hashinput4[1] = DevicePW[1];
    hashinput4[2] = NonceB[0];
    hashinput4[3] = NonceB[1];
    sha512(P2,hashinput4,4);
    
    printf("**** Send c2, p2 ****\n");
    
    crypto_kem_dec(Message,c2,sk);
    //Verify P2
    hashinput4[2] = Message[2];
    hashinput4[3] = Message[3];
    sha512(VP2,hashinput4,4);
    
    if(memcmp(P2,VP2,HASH_LEN) == 0)
            printf("Verify P2 Succeed\n");
     else{
         hashinput4[0] = PWtemp[0];
         hashinput4[1] = PWtemp[1];
         sha512(VP2,hashinput4,4);
         if(memcmp(P2,VP2,HASH_LEN) == 0)
                    printf("Verify P2 Succeed\n");
         else{
         printf("Verify P1 Failed");
         return 0;
         }
     }
    
    //Update Database
    PWtemp[0] = ServerPW[0];
    PWtemp[1] = ServerPW[1];
    ServerPW[0] = ServerPW[0] ^ Message[2];
    ServerPW[1] = ServerPW[1] ^ Message[3];
    
    //Compute P3
    sha512(P3,ServerPW,2);
    
    printf("**** Send P3 ****\n");
    
    //Verify P3
    hashinput2[0] = DevicePW[0] ^ NonceB[0];
    hashinput2[1] = DevicePW[1] ^ NonceB[1];
    sha512(VP3, hashinput2,2);

    if(memcmp(P3,VP3,HASH_LEN) == 0){
           printf("Verify P3 Succeed\n");
    DevicePW[0] = hashinput2[0];
    DevicePW[1] = hashinput2[1];
    }
    else{
        printf("Verify P3 Failed");
        return 0;
    }
    
    //Compute P4
    hashinput2[0] = DevicePW[0] ^ Deviceid[0];
    hashinput2[1] = DevicePW[1] ^ Deviceid[1];
    sha512(P4, hashinput2, 2);
    
    //Establish Device Session Key
    hashinput4[0] = DevicePW[0];
    hashinput4[1] = DevicePW[1];
    hashinput4[2] = Deviceid[0];
    hashinput4[3] = Deviceid[1];
    sha512(ss1, hashinput4, 4);
    
    printf("**** Send P4 ****\n");
    
    //Verify P4
    hashinput2[0] = ServerPW[0] ^ Message[0];
    hashinput2[1] = ServerPW[1] ^ Message[1];
    sha512(VP4,hashinput2,2);
    if(memcmp(P4,VP4,HASH_LEN) == 0){
           printf("Verify P4 Succeed\n");
        //Update Pwtemp and Establish Session Key
        PWtemp[0] = NULL;
        PWtemp[1] = NULL;
        hashinput4[0] = ServerPW[0];
        hashinput4[1] = ServerPW[1];
        hashinput4[2] = Message[0];
        hashinput4[3] = Message[1];
        sha512(ss2, hashinput4, 4);
    }
    else{
        printf("Verify P4 Failed");
        return 0;
    }
    return 1;

}
