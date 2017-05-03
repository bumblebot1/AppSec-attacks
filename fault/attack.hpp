#ifndef __ATTACK_HPP
#define __ATTACK_HPP

#include <iostream>
#include  <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <vector>

#include  <signal.h>
#include  <unistd.h>
#include   <fcntl.h>

#include "galois_multiples.hpp"
#include "aes_params.hpp"
#include <openssl/aes.h>

using namespace std;

class Attack {
    private:
        FILE* target_in;
        FILE* target_out;
        int interactionCount = 0;
        vector<vector<uint8_t>> kAll;
        void (*cleanup)(int s);
        int keyFound = 0;

    private:
        void RandomMessage(uint8_t m[16]);
        int Equation1(const uint8_t c[16], const uint8_t c_fault[16]);
        int Equation2(const uint8_t c[16], const uint8_t c_fault[16]);
        int Equation3(const uint8_t c[16], const uint8_t c_fault[16]);
        int Equation4(const uint8_t c[16], const uint8_t c_fault[16]);
        uint8_t SecondEquation1(const uint8_t c[16], const uint8_t c_fault[16], const uint8_t k[16], const uint8_t k9[16]);
        uint8_t SecondEquation2(const uint8_t c[16], const uint8_t c_fault[16], const uint8_t k[16], const uint8_t k9[16]);
        uint8_t SecondEquation3(const uint8_t c[16], const uint8_t c_fault[16], const uint8_t k[16], const uint8_t k9[16]);
        uint8_t SecondEquation4(const uint8_t c[16], const uint8_t c_fault[16], const uint8_t k[16], const uint8_t k9[16]);
        void PrintKey(const uint8_t key[16]);
        void OriginalKey(uint8_t k[16], int currentRound);
        void RoundKey(uint8_t k[16], const int r);
        void Interact(uint8_t c[16], const int fault, const int r, const int f , const int p, const int i, const int j, const uint8_t m[16]);
    
    public:
        Attack(FILE* in, FILE* out, void (*clean)(int s));
        void Execute();
};

Attack::Attack(FILE* in, FILE* out, void (*clean)(int s)){
  kAll.reserve(16);
  target_in  = in;
  target_out = out;
  cleanup    = clean;
}

// generate random messages for multiple measurements
void Attack::RandomMessage(uint8_t m[16]){
  // open file to read random bytes from
  FILE *f = fopen("/dev/urandom", "rb");
  int l = fread(m, 1, 16, f);
  if(l != 16) {
    exit(EXIT_FAILURE);
  }
  printf("Randomly chosen plaintext is:\n");
  PrintKey(m);
  printf("\n");
  fclose(f);
}

void Attack::Execute(){
  uint8_t input[16];
  uint8_t c[16];
  uint8_t faulty_c[16];
  int set1, set2, set3, set4;
  int tested_keys = 0;

  // get random messages
  RandomMessage(input);

  Interact(c, 0, 8, 1, 0, 0, 0, input);
  Interact(faulty_c, 1, 8, 1, 0, 0, 0, input);

  // k1, k8, k11, k14
  set1 = Equation1(c, faulty_c);
  printf("%d possibilities for k1 , k8 , k11, k14\n", set1);
  // k5, k2, k15, k12
  set2 = Equation2(c,faulty_c);
  printf("%d possibilities for k2 , k5 , k12, k15\n", set2);
  // k9, k6, k3, k16
  set3 = Equation3(c, faulty_c);
  printf("%d possibilities for k3 , k6 , k9 , k16\n", set3);
  // k13, k10, k7, k4
  set4 = Equation4(c, faulty_c);
  printf("%d possibilities for k4 , k7, k10 , k13\n", set4);


  printf("Computing last set of equations\n");
  #pragma omp parallel for
  for(int j1 = 0; j1< set1; j1++){
    for(int j2 = 0; j2 < set2; j2++){
      for(int j3 = 0; j3 < set3; j3++){
        for(int j4 = 0; j4 < set4; j4++){
          uint8_t k[16];
          uint8_t k9[16];
          // key guess after round 10
          k[0]  = kAll[0][j1];  k[7]  = kAll[7][j1];  k[10] = kAll[10][j1];   k[13] = kAll[13][j1];
          k[4]  = kAll[4][j2];  k[1]  = kAll[1][j2];  k[14] = kAll[14][j2];   k[11] = kAll[11][j2];
          k[8]  = kAll[8][j3];  k[5]  = kAll[5][j3];  k[2]  = kAll[2][j3];    k[15] = kAll[15][j3];
          k[12] = kAll[12][j4]; k[9]  = kAll[9][j4];  k[6]  = kAll[6][j4];    k[3]  = kAll[3][j4];

          // same key guess after round 10
          k9[0]  = kAll[0][j1];   k9[7]  = kAll[7][j1];   k9[10] = kAll[10][j1];  k9[13] = kAll[13][j1];
          k9[4]  = kAll[4][j2];   k9[1]  = kAll[1][j2];   k9[14] = kAll[14][j2];  k9[11] = kAll[11][j2];
          k9[8]  = kAll[8][j3];   k9[5]  = kAll[5][j3];   k9[2]  = kAll[2][j3];   k9[15] = kAll[15][j3];
          k9[12] = kAll[12][j4];  k9[9]  = kAll[9][j4];   k9[6]  = kAll[6][j4];   k9[3]  = kAll[3][j4];

          // get key from round 9
          RoundKey(k9, 10);

          // get result of equation
          uint8_t f = SecondEquation2(c, faulty_c, k, k9);

          // check te above result against the other 3 results
          if( f == SecondEquation3(c, faulty_c, k, k9) &&  (GaloisTable3[f] == SecondEquation4(c, faulty_c, k, k9)) && (GaloisTable2[f] == SecondEquation1(c, faulty_c, k, k9)) ) {
            tested_keys = tested_keys + 1;
            if(tested_keys % 5 == 0)
              printf("potential keys tested: %d \n", tested_keys  );
            // get original key used for encryption
            OriginalKey(k9, 9);

            // simulate AES encryption using the retrieved key
            AES_KEY rk;
            AES_set_encrypt_key( k9, 128, &rk );
            uint8_t result[16];
            AES_encrypt( input, result, &rk );

            // if result is right, found key
            if( !memcmp( result, c, 16 * sizeof( uint8_t ) ) ) {
              printf("potential keys tested: %d \n", tested_keys  );
              printf( "Key found: ");
              PrintKey(k9);
              printf("interactions with the oracle: %d\n", interactionCount);
              keyFound = 1;
              exit(EXIT_SUCCESS);
            }
          }
        }
      }
    }
  }
  cout<<kAll[0].size();
  printf("!!!!!!Key not found, something might have gone wrong, try again !!!!\n");
}

void Attack::Interact(uint8_t c[16], const int fault, const int r, const int f , const int p, const int i, const int j, const uint8_t m[16]) {
  if(fault) {
    fprintf( target_in, "%d,%d,%d,%d,%d", r, f, p, i, j );
  }
  fprintf(target_in, "\n");

  for(int l = 0; l < 16; l++){
    fprintf(target_in, "%02X",  m[l]);
  }
  fprintf(target_in,"\n");
  fflush( target_in );

  // Receive ( t, r ) from attack target.
  for(int l = 0; l < 16; l++){
    if( 1 != fscanf( target_out, "%2hhx", &c[l] ) ) {
      abort();
    }
  }
  interactionCount++;
}


int Attack::Equation1(const uint8_t c[16], const uint8_t c_fault[16]){
  int k1, k8, k11, k14, delta;
  int possibilities;
  possibilities = 0;
  for(delta=1; delta <= 0xFF; delta++){
    for(k1 = 0; k1 <= 0xFF; k1++){
      if(GaloisTable2[delta] == (inv_s[c[0] ^ k1] ^ inv_s[c_fault[0] ^ k1]) ){

      for(k14 = 0; k14 <= 0xFF; k14++){
        if(delta == (inv_s[c[13]^ k14] ^ inv_s[c_fault[13] ^ k14]) )

        for(k11 = 0; k11<= 0xFF; k11++){
          if(delta == (inv_s[c[10] ^ k11] ^ inv_s[c_fault[10] ^ k11]) )

          for(k8 = 0; k8<= 0xFF; k8++){
            if(GaloisTable3[delta] == (inv_s[c[7] ^ k8] ^ inv_s[c_fault[7] ^ k8]) ){
              kAll[0].push_back(k1);
              kAll[7].push_back(k8);
              kAll[10].push_back(k11);
              kAll[13].push_back(k14);
              possibilities++;
            }
          }
        }
      }
     }
   }
  }
  return possibilities;
}


int Attack::Equation2(const uint8_t c[16], const uint8_t c_fault[16]){
  int k5, k2, k15, k12, delta;
  int possibilities = 0;
  for(delta=1; delta <= 0xFF; delta++){
    
    for(k5 = 0; k5 <= 0xFF; k5++){
      if(delta == (inv_s[c[4] ^ k5] ^ inv_s[c_fault[4] ^ k5]) ){
        
        for(k2 = 0; k2 <= 0xFF; k2++){
          if(delta == (inv_s[c[1]^ k2] ^ inv_s[c_fault[1] ^ k2]) )
          
          for(k15 = 0; k15<= 0xFF; k15++){
            if(GaloisTable3[delta]== (inv_s[c[14] ^ k15] ^ inv_s[c_fault[14] ^ k15]) )
            
            for(k12 = 0; k12<= 0xFF; k12++){
              if(GaloisTable2[delta] == (inv_s[c[11] ^ k12] ^ inv_s[c_fault[11] ^ k12]) ){
                kAll[1].push_back(k2);
                kAll[4].push_back(k5);
                kAll[11].push_back(k12);
                kAll[14].push_back(k15);
                possibilities++;
              }
            }
          }
        }
      }
    }
  }
  
  return possibilities;
}

int Attack::Equation3(const uint8_t c[16], const uint8_t c_fault[16]){
  int k9, k6, k3, k16, delta;
  int possibilities = 0;
  for(delta=1; delta <= 0xFF; delta++){
    
    for(k9 = 0; k9 <= 0xFF; k9++){
      if(delta == (inv_s[c[8] ^ k9] ^ inv_s[c_fault[8] ^ k9]) ){

        for(k6 = 0; k6 <= 0xFF; k6++){
          if(GaloisTable3[delta] == (inv_s[c[5]^ k6] ^ inv_s[c_fault[5] ^ k6]) )

          for(k3 = 0; k3<= 0xFF; k3++){
            if(GaloisTable2[delta] == (inv_s[c[2] ^ k3] ^ inv_s[c_fault[2] ^ k3]) )

            for(k16 = 0; k16<= 0xFF; k16++){
              if(delta == (inv_s[c[15] ^ k16] ^ inv_s[c_fault[15] ^ k16]) ){
                kAll[2].push_back(k3);
                kAll[5].push_back(k6);
                kAll[8].push_back(k9);
                kAll[15].push_back(k16);
                possibilities++;
              }
            }
          }
        }
      }
    }
  }
  return possibilities;
}

int Attack::Equation4(const uint8_t c[16], const uint8_t c_fault[16]){
  int k13, k10, k7, k4, delta;
  int possibilities = 0;
  for(delta=1; delta <= 0xFF; delta++){
    
    for(k13 = 0; k13 <= 0xFF; k13++){
      if(GaloisTable3[delta] == (inv_s[c[12] ^ k13] ^ inv_s[c_fault[12] ^ k13]) ){

        for(k10 = 0; k10 <= 0xFF; k10++){
          if( GaloisTable2[delta] == (inv_s[c[9]^ k10] ^ inv_s[c_fault[9] ^ k10]) )

          for(k7 = 0; k7<= 0xFF; k7++){
            if(delta == (inv_s[c[6] ^ k7] ^ inv_s[c_fault[6] ^ k7]) )

            for(k4 = 0; k4<= 0xFF; k4++){
              if(delta == (inv_s[c[3] ^ k4] ^ inv_s[c_fault[3] ^ k4]) ){
                kAll[3].push_back(k4);
                kAll[6].push_back(k7);
                kAll[9].push_back(k10);
                kAll[12].push_back(k13);
                possibilities++;
              }
            }
          }
        }
      }
    }
  } 
  return possibilities;
}

uint8_t Attack::SecondEquation1(const uint8_t c[16], const uint8_t c_fault[16], const uint8_t k[16], const uint8_t k9[16]){
  uint8_t a, b;

  a = GaloisTable14[inv_s[ c[0]  ^  k[0] ] ^ k9[0] ] ^
      GaloisTable11[inv_s[ c[13] ^ k[13] ] ^ k9[1] ] ^
      GaloisTable13[inv_s[ c[10] ^ k[10] ] ^ k9[2] ] ^
      GaloisTable9 [inv_s[ c[7]  ^  k[7] ] ^ k9[3] ];
  
  b = GaloisTable14[inv_s[ c_fault[0]  ^  k[0] ] ^ k9[0] ] ^
      GaloisTable11[inv_s[ c_fault[13] ^ k[13] ] ^ k9[1] ] ^
      GaloisTable13[inv_s[ c_fault[10] ^ k[10] ] ^ k9[2] ] ^
      GaloisTable9 [inv_s[ c_fault[7]  ^  k[7] ] ^ k9[3] ];

  return inv_s[a] ^ inv_s[b];
}

uint8_t Attack::SecondEquation2(const uint8_t c[16], const uint8_t c_fault[16], const uint8_t k[16], const uint8_t k9[16]){
  uint8_t a, b;

  a = GaloisTable9 [ inv_s[ c[12] ^ k[12] ] ^ k9[12] ] ^
      GaloisTable14[ inv_s[ c[9]  ^  k[9] ] ^ k9[13] ] ^
      GaloisTable11[ inv_s[ c[6]  ^  k[6] ] ^ k9[14] ] ^
      GaloisTable13[ inv_s[ c[3]  ^  k[3] ] ^ k9[15] ];

  b = GaloisTable9 [ inv_s[ c_fault[12] ^ k[12] ] ^  k9[12] ] ^
      GaloisTable14[ inv_s[ c_fault[9]  ^  k[9] ] ^  k9[13] ] ^
      GaloisTable11[ inv_s[ c_fault[6]  ^  k[6] ] ^  k9[14] ] ^
      GaloisTable13[ inv_s[ c_fault[3]  ^  k[3] ] ^  k9[15] ];

  return inv_s[a] ^ inv_s[b];
}

uint8_t Attack::SecondEquation3(const uint8_t c[16], const uint8_t c_fault[16], const uint8_t k[16], const uint8_t k9[16]){
  uint8_t a, b;
  a = GaloisTable13[inv_s[ c[8]  ^  k[8] ] ^ k9[8] ] ^
      GaloisTable9 [inv_s[ c[5]  ^  k[5] ] ^ k9[9] ] ^
      GaloisTable14[inv_s[ c[2]  ^  k[2] ] ^ k9[10]] ^
      GaloisTable11[inv_s[ c[15] ^ k[15] ] ^ k9[11]];
          
  b = GaloisTable13[inv_s[ c_fault[8]  ^  k[8] ] ^ k9[8] ] ^
      GaloisTable9 [inv_s[ c_fault[5]  ^  k[5] ] ^ k9[9] ] ^
      GaloisTable14[inv_s[ c_fault[2]  ^  k[2] ] ^ k9[10]] ^
      GaloisTable11[inv_s[ c_fault[15] ^ k[15] ] ^ k9[11]];

  return inv_s[a] ^ inv_s[b];
}

uint8_t Attack::SecondEquation4(const uint8_t c[16], const uint8_t c_fault[16], const uint8_t k[16], const uint8_t k9[16]){
  uint8_t a ,b;


  a = GaloisTable11[inv_s[ c[4]  ^ k[4]  ] ^ k9[4]] ^
      GaloisTable13[inv_s[ c[1]  ^ k[1]  ] ^ k9[5]] ^
      GaloisTable9 [inv_s[ c[14] ^ k[14] ] ^ k9[6]] ^
      GaloisTable14[inv_s[ c[11] ^ k[11] ] ^ k9[7]];
  
  b = GaloisTable11[inv_s[ c_fault[4]  ^ k[4]  ] ^ k9[4]] ^
      GaloisTable13[inv_s[ c_fault[1]  ^ k[1]  ] ^ k9[5]] ^
      GaloisTable9 [inv_s[ c_fault[14] ^ k[14] ] ^ k9[6]] ^
      GaloisTable14[inv_s[ c_fault[11] ^ k[11] ] ^ k9[7]];

  return inv_s[a] ^ inv_s[b];
}

void Attack::OriginalKey(uint8_t k[16], int currentRound){
  for(int i=currentRound; i>0; i--){
    RoundKey(k, i);
  }
}

void Attack::RoundKey(uint8_t k[16], const int r){
  k[12] ^=  k[8];
  k[13] ^=  k[9];
  k[14] ^=  k[10];
  k[15] ^=  k[11];

  k[8]  ^=  k[4];
  k[9]  ^=  k[5];
  k[10] ^=  k[6];
  k[11] ^=  k[7];

  k[4] ^= k[0];
  k[5] ^= k[1];
  k[6] ^= k[2];
  k[7] ^= k[3];

  k[0] ^=  s[k[13]] ^ rcon[r];
  k[1] ^=  s[k[14]];
  k[2] ^=  s[k[15]];
  k[3] ^=  s[k[12]];
}

void Attack::PrintKey(const uint8_t key[16]){
  for(int i=0; i<16; i++){
    printf("%02X", key[i]);
  }
  printf("\n");
}

#endif
