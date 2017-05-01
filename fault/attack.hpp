#ifndef __ATTACK_HPP
#define __ATTACK_HPP

#include  <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include  <signal.h>
#include  <unistd.h>
#include   <fcntl.h>

#include "galois_multiples.hpp"
#include "aes_params.hpp"
#include <openssl/aes.h>

#define sampleSize 1

class Attack {
    private:
        FILE* target_in;
        FILE* target_out;
        unsigned long interactions;
        void (*cleanup)(int s);
        int keyFound = 0;

    private:
        void generateRandomMessage(uint8_t m[sampleSize][16]);
        int setsEquation1(const uint8_t x[][16], const uint8_t x1[][16], uint8_t k[16][1024]);
        int setsEquation2(const uint8_t x[][16], const uint8_t x1[][16], uint8_t k[16][1024]);
        int setsEquation3(const uint8_t x[][16], const uint8_t x1[][16], uint8_t k[16][1024]);
        int setsEquation4(const uint8_t x[][16], const uint8_t x1[][16], uint8_t k[16][1024]);
        uint8_t fEquation1(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]);
        uint8_t fEquation2(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]);
        uint8_t fEquation3(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]);
        uint8_t fEquation4(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]);
        void printState(const uint8_t state[16]);
        void getOriginalKey(uint8_t k[16], int currentRound);
        void getRoundK(uint8_t k[16], const int r);
        void interact(uint8_t c[16], const int fault, const int r, const int f , const int p, const int i, const int j, const uint8_t m[16]);
    
    public:
        Attack(FILE* in, FILE* out, void (*clean)(int s));
        void Execute();
};

Attack::Attack(FILE* in, FILE* out, void (*clean)(int s)){
    target_in = in;
    target_out = out;
    cleanup = clean;
}

// generate random messages for multiple measurements
void Attack::generateRandomMessage(uint8_t m[sampleSize][16]){
  // open file to read random bytes from
  FILE *fp = fopen("/dev/urandom", "r");
  int character;
  for(int i=0; i< sampleSize; i++){
    for(int j=0; j<16; j++){
      character = fgetc(fp);
      m[i][j] = character;
    }
  }

  // close file
  fclose(fp);

}

void Attack::Execute(){
  uint8_t input[sampleSize][16];
  uint8_t c[sampleSize][16];
  uint8_t faulty_c[sampleSize][16];
  uint8_t kAll[16][1024];
  int set1, set2, set3, set4;
  uint8_t k[16];
  uint8_t k9[16];
  uint8_t result[16];
  uint8_t f;
  int tested_keys = 0;

  // get random messages
  generateRandomMessage(input);

  // get correct ciphertext
  for(int i=0; i<sampleSize; i++)
    interact(c[i], 0, 8, 1, 0, 0, 0, input[i]);

  // get faulty ciphertext
  for(int i=0; i<sampleSize; i++)
    interact(faulty_c[i], 1, 8, 1, 0, 0, 0, input[i]);

  // k1, k8, k11, k14
  set1 = setsEquation1(c, faulty_c, kAll);
  printf("%d possibilities for k1 , k8 , k11, k14\n", set1);
  // k5, k2, k15, k12
  set2 = setsEquation2(c,faulty_c, kAll);
  printf("%d possibilities for k5 , k2 , k15, k12\n", set2);
  // k9, k6, k3, k16
  set3 = setsEquation3(c, faulty_c, kAll);
  printf("%d possibilities for k9 , k6 , k3 , k16\n", set3);
  // k13, k10, k7, k4
  set4 = setsEquation4(c, faulty_c, kAll);
  printf("%d possibilities for k13, k10, k7 , k4 \n", set4);


  printf("Computing last set of equations\n");
  #pragma omp parallel for schedule(auto) private(k, k9, result, f)
  for(int j1 = 0; j1< set1; j1++){
    for(int j2 = 0; j2 < set2; j2++){
      for(int j3 = 0; j3 < set3; j3++){
        for(int j4 = 0; j4 < set4; j4++){
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
          getRoundK(k9, 10);

          // get result of equation
          f = fEquation2(c[0], faulty_c[0], k, k9);

          // check te above result against the other 3 results
          if( f == fEquation3(c[0], faulty_c[0], k, k9) &&  (GaloisTable3[f] == fEquation4(c[0], faulty_c[0], k, k9)) && (GaloisTable2[f] == fEquation1(c[0], faulty_c[0], k, k9)) ) {
            tested_keys = tested_keys + 1;
            if(tested_keys % 5 == 0)
              printf("potential keys tested: %d \n", tested_keys  );
            // get original key used for encryption
            getOriginalKey(k9, 9);

            // simulate AES encryption using the retrieved key
            AES_KEY rk;
            AES_set_encrypt_key( k9, 128, &rk );
            AES_encrypt( input[0], result, &rk );

            // if result is right, found key
            if( !memcmp( result, c[0], 16 * sizeof( uint8_t ) ) ) {
              printf("potential keys tested: %d \n", tested_keys  );
              printf( "Key found: ");
              printState(k9);
              printf("interactions with the oracle: %d\n", interactions);
              keyFound = 1;
              exit(EXIT_SUCCESS);
            }
          }
        }
      }
    }
  }
  printf("!!!!!!Key not found, something might have gone wrong, try again !!!!\n");
}

void Attack::interact(uint8_t c[16], const int fault, const int r, const int f , const int p, const int i, const int j, const uint8_t m[16]) {
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
  interactions++;
}


int Attack::setsEquation1(const uint8_t x[sampleSize][16], const uint8_t x1[sampleSize][16], uint8_t kAll[16][1024] ){
  int k1, k8, k11, k14, ro;
  uint8_t k[sampleSize][16][1024];
  int possibilities[sampleSize];
  for(int i=0; i<sampleSize; i++){
    possibilities[i] = 0;
    for(ro=1; ro <= 0xFF; ro++){

      for(k1 = 0; k1 <= 0xFF; k1++){
        if(GaloisTable2[ro] == (inv_s[x[i][0] ^ k1] ^ inv_s[x1[i][0] ^ k1]) ){
          for(k14 = 0; k14 <= 0xFF; k14++){

            if(ro == (inv_s[x[i][13]^ k14] ^ inv_s[x1[i][13] ^ k14]) )
              for(k11 = 0; k11<= 0xFF; k11++){

                if(ro == (inv_s[x[i][10] ^ k11] ^ inv_s[x1[i][10] ^ k11]) )
                  for(k8 = 0; k8<= 0xFF; k8++){

                    if(GaloisTable3[ro] == (inv_s[x[i][7] ^ k8] ^ inv_s[x1[i][7] ^ k8]) ){
                      k[i][0][possibilities[i]]  = k1;
                      k[i][13][possibilities[i]] = k14;
                      k[i][10][possibilities[i]] = k11;
                      k[i][7][possibilities[i]]  = k8;
                      possibilities[i]++;
                }
              }
            }
          }
        }
      }
    }
    // printf("message %d has %d poss\n",i, possibilities[i] );
  }
  int poss = 0, check = 1;
  for( int j=0; j<possibilities[0]; j++){
    k1 = k[0][0][j];
    k14 = k[0][13][j];
    k11 = k[0][10][j];
    k8 = k[0][7][j];
    check = 1;
    for(int i=1; i<sampleSize && check == 1; i++){
      check = 0;
      for(int j1 = 0; j1<possibilities[i]; j1++){
        if( k1 == k[i][0][j1] && k14 == k[i][13][j1] && k11 == k[i][10][j1] && k8 == k[i][7][j1] ){
          check = 1;
          // printf("message %d : %02X %02X %02X %02X\n", i, k1, k14, k11, k8);
        }
      }
    }
    if(check == 1){
      kAll[0][poss] = k1;
      kAll[13][poss] = k14;
      kAll[10][poss] = k11;
      kAll[7][poss] = k8;
      poss++;
    }
  }
  // printf("poss = %d\n",poss );
  return poss;
}


int Attack::setsEquation2(const uint8_t x[sampleSize][16], const uint8_t x1[sampleSize][16], uint8_t kAll[16][1024] ){
  int k5, k2, k15, k12, ro;
  uint8_t k[sampleSize][16][1024];
  int possibilities[sampleSize];
  for(int i=0; i<sampleSize; i++){
    possibilities[i] = 0;
    for(ro=1; ro <= 0xFF; ro++){
      for(k5 = 0; k5 <= 0xFF; k5++){

        if(ro == (inv_s[x[i][4] ^ k5] ^ inv_s[x1[i][4] ^ k5]) ){
          for(k2 = 0; k2 <= 0xFF; k2++){

            if(ro == (inv_s[x[i][1]^ k2] ^ inv_s[x1[i][1] ^ k2]) )
            for(k15 = 0; k15<= 0xFF; k15++){

              if(GaloisTable3[ro]== (inv_s[x[i][14] ^ k15] ^ inv_s[x1[i][14] ^ k15]) )
              for(k12 = 0; k12<= 0xFF; k12++){

                if(GaloisTable2[ro] == (inv_s[x[i][11] ^ k12] ^ inv_s[x1[i][11] ^ k12]) ){
                  k[i][4][possibilities[i]]   = k5;
                  k[i][1][possibilities[i]]   = k2;
                  k[i][14][possibilities[i]]  = k15;
                  k[i][11][possibilities[i]]  = k12;
                  possibilities[i]++;
                }
              }
            }
          }
        }
      }
    }
    // printf("message %d has %d poss\n",i, possibilities[i] );
  }
  int poss = 0, check = 1;
  for( int j=0; j<possibilities[0]; j++){
    k5 = k[0][4][j];
    k2 = k[0][1][j];
    k15 = k[0][14][j];
    k12 = k[0][11][j];
    check = 1;
    for(int i=1; i<sampleSize && check == 1; i++){
      check = 0;
      for(int j1 = 0; j1<possibilities[i]; j1++){
        if( k5 == k[i][4][j1] && k2 == k[i][1][j1] && k15 == k[i][14][j1] && k12 == k[i][11][j1] ){
          check = 1;
          // printf("%02X %02X %02X %02X\n", k5, k2, k15, k12);
        }
      }
    }
    if(check == 1){
      kAll[4][poss] = k5;
      kAll[1][poss] = k2;
      kAll[14][poss] = k15;
      kAll[11][poss] = k12;
      poss++;
    }
  }
  // printf("poss = %d\n",poss );
  return poss;
}

int Attack::setsEquation3(const uint8_t x[sampleSize][16], const uint8_t x1[sampleSize][16], uint8_t kAll[16][1024] ){
  int k9, k6, k3, k16, ro;
  uint8_t k[sampleSize][16][1024];
  int possibilities[sampleSize];
  for(int i=0; i<sampleSize; i++){
    possibilities[i] = 0;
    for(ro=1; ro <= 0xFF; ro++){
      for(k9 = 0; k9 <= 0xFF; k9++){

        if(ro == (inv_s[x[i][8] ^ k9] ^ inv_s[x1[i][8] ^ k9]) ){
          for(k6 = 0; k6 <= 0xFF; k6++){

            if(GaloisTable3[ro] == (inv_s[x[i][5]^ k6] ^ inv_s[x1[i][5] ^ k6]) )
            for(k3 = 0; k3<= 0xFF; k3++){

              if(GaloisTable2[ro] == (inv_s[x[i][2] ^ k3] ^ inv_s[x1[i][2] ^ k3]) )
              for(k16 = 0; k16<= 0xFF; k16++){

                if(ro == (inv_s[x[i][15] ^ k16] ^ inv_s[x1[i][15] ^ k16]) ){
                  k[i][8][possibilities[i]]   = k9;
                  k[i][5][possibilities[i]]   = k6;
                  k[i][2][possibilities[i]]   = k3;
                  k[i][15][possibilities[i]]  = k16;
                  possibilities[i]++;
                }
              }
            }
          }
        }
      }
    }
    // printf("message %d has %d poss\n",i, possibilities[i] );
  }
  int poss = 0, check = 1;
  for( int j=0; j<possibilities[0]; j++){
    k9 = k[0][8][j];
    k6 = k[0][5][j];
    k3 = k[0][2][j];
    k16 = k[0][15][j];
    check = 1;
    for(int i=1; i<sampleSize && check == 1; i++){
      check = 0;
      for(int j1 = 0; j1<possibilities[i]; j1++){
        if( k9 == k[i][8][j1] && k6 == k[i][5][j1] && k3 == k[i][2][j1] && k16 == k[i][15][j1] ){
          check = 1;
          // printf("%02X %02X %02X %02X\n", k9, k6, k3, k16);
        }
      }
    }
    if(check == 1){
      kAll[8][poss] = k9;
      kAll[5][poss] = k6;
      kAll[2][poss] = k3;
      kAll[15][poss] = k16;
      poss++;
    }
  }
  // printf("poss = %d\n",poss );
  return poss;
}

int Attack::setsEquation4(const uint8_t x[sampleSize][16], const uint8_t x1[sampleSize][16], uint8_t kAll[16][1024] ){
  int k13, k10, k7, k4, ro;
  uint8_t k[sampleSize][16][1024];
  int possibilities[sampleSize];
  for(int i=0; i<sampleSize; i++){
    possibilities[i] = 0;
    for(ro=1; ro <= 0xFF; ro++){
      for(k13 = 0; k13 <= 0xFF; k13++){

        if(GaloisTable3[ro] == (inv_s[x[i][12] ^ k13] ^ inv_s[x1[i][12] ^ k13]) ){
          for(k10 = 0; k10 <= 0xFF; k10++){

            if( GaloisTable2[ro] == (inv_s[x[i][9]^ k10] ^ inv_s[x1[i][9] ^ k10]) )
            for(k7 = 0; k7<= 0xFF; k7++){

              if(ro == (inv_s[x[i][6] ^ k7] ^ inv_s[x1[i][6] ^ k7]) )
              for(k4 = 0; k4<= 0xFF; k4++){

                if(ro == (inv_s[x[i][3] ^ k4] ^ inv_s[x1[i][3 ] ^ k4]) ){
                  k[i][12][possibilities[i]]  = k13;
                  k[i][9][possibilities[i]]   = k10;
                  k[i][6][possibilities[i]]   = k7;
                  k[i][3][possibilities[i]]   = k4;
                  possibilities[i]++;
                }
              }
            }
          }
        }
      }
    }
    // printf("message %d has %d poss\n",i, possibilities[i] );
  }
  int poss = 0, check = 1;
  for( int j=0; j<possibilities[0]; j++){
    k13 = k[0][12][j];
    k10 = k[0][9][j];
    k7  = k[0][6][j];
    k4  = k[0][3][j];
    check = 1;
    for(int i=1; i<sampleSize && check == 1; i++){
      check = 0;
      for(int j1 = 0; j1<possibilities[i]; j1++){
        if( k13 == k[i][12][j1] && k10 == k[i][9][j1] && k7 == k[i][6][j1] && k4 == k[i][3][j1] ){
          check = 1;
          // printf("%02X %02X %02X %02X\n", k13, k10, k7, k4);
        }
      }
    }
    if(check == 1){
      kAll[12][poss] = k13;
      kAll[9][poss] = k10;
      kAll[6][poss] = k7;
      kAll[3][poss] = k4;
      poss++;
    }
  }
  // printf("poss = %d\n",poss );
  return poss;
}

uint8_t Attack::fEquation1(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]){
  uint8_t result;

  result = inv_s[ GaloisTable14[ inv_s[ x[0]  ^  k[0] ] ^ k9[0] ] ^
                  GaloisTable11[ inv_s[ x[13] ^ k[13] ] ^ k9[1] ] ^
                  GaloisTable13[ inv_s[ x[10] ^ k[10] ] ^ k9[2] ] ^
                  GaloisTable9[ inv_s[  x[7] ^  k[7] ] ^ k9[3] ]
                ] ^
          inv_s[ GaloisTable14[ inv_s[ x1[0]  ^  k[0] ] ^ k9[0] ] ^
                 GaloisTable11[ inv_s[ x1[13] ^ k[13] ] ^ k9[1] ] ^
                 GaloisTable13[ inv_s[ x1[10] ^ k[10] ] ^ k9[2] ] ^
                 GaloisTable9[ inv_s[  x1[7] ^  k[7] ] ^ k9[3] ]
              ];
  return result;
}

uint8_t Attack::fEquation2(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]){
  uint8_t a, b;
  uint8_t result1;

  a = GaloisTable9[ inv_s[ x[12] ^ k[12] ] ^ k9[12] ] ^
      GaloisTable14[ inv_s[ x[9]  ^  k[9] ] ^ k9[13] ] ^
      GaloisTable11[ inv_s[ x[6]  ^  k[6] ] ^ k9[14] ] ^
      GaloisTable13[ inv_s[ x[3]  ^  k[3] ] ^ k9[15] ];

  b = GaloisTable9[ inv_s[ x1[12] ^ k[12] ] ^  k9[12] ] ^
      GaloisTable14[ inv_s[ x1[9]  ^  k[9] ] ^  k9[13] ] ^
      GaloisTable11[ inv_s[ x1[6]  ^  k[6] ] ^  k9[14] ] ^
      GaloisTable13[ inv_s[ x1[3]  ^  k[3] ] ^  k9[15] ];

  result1 = inv_s[ a] ^ inv_s[ b ] ;

  return result1;
}

uint8_t Attack::fEquation3(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]){
  uint8_t result;

  result = inv_s[ GaloisTable13[ inv_s[ x[8]  ^  k[8] ] ^ k9[8]  ] ^
                  GaloisTable9[ inv_s[ x[5]  ^  k[5] ] ^ k9[9]  ] ^
                  GaloisTable14[ inv_s[ x[2]  ^  k[2] ] ^ k9[10] ] ^
                  GaloisTable11[ inv_s[ x[15] ^ k[15] ] ^ k9[11] ]
                ] ^
          inv_s[ GaloisTable13[ inv_s[ x1[8]  ^  k[8] ] ^ k9[8]  ] ^
                 GaloisTable9[ inv_s[ x1[5]  ^  k[5] ] ^ k9[9]  ] ^
                 GaloisTable14[ inv_s[ x1[2]  ^  k[2] ] ^ k9[10] ] ^
                 GaloisTable11[ inv_s[ x1[15] ^ k[15] ] ^ k9[11] ]
               ] ;
  return result;
}

uint8_t Attack::fEquation4(const uint8_t x[16], const uint8_t x1[16], const uint8_t k[16], const uint8_t k9[16]){
  uint8_t result;


  result = inv_s[ GaloisTable11[ inv_s[ x[4 ] ^ k[4 ] ] ^ k9[4] ] ^
                  GaloisTable13[ inv_s[ x[1 ] ^ k[1 ] ] ^ k9[5] ] ^
                  GaloisTable9[ inv_s[ x[14] ^ k[14] ] ^ k9[6] ] ^
                  GaloisTable14[ inv_s[ x[11] ^ k[11] ] ^ k9[7] ]
                ] ^
          inv_s[ GaloisTable11[ inv_s[ x1[4 ] ^ k[4 ] ] ^ k9[4] ] ^
                 GaloisTable13[ inv_s[ x1[1]  ^ k[1 ] ] ^ k9[5] ] ^
                 GaloisTable9[ inv_s[ x1[14] ^ k[14] ] ^ k9[6] ] ^
                 GaloisTable14[ inv_s[ x1[11] ^ k[11] ] ^ k9[7] ]
              ];
  return result;
}

void Attack::getOriginalKey(uint8_t k[16], int currentRound){
  for(int i=currentRound; i>0; i--){
    getRoundK(k, i);
  }
}

void Attack::getRoundK(uint8_t k[16], const int r){
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

  k[0] ^=  s[ k[13]  ] ^ rcon[r];
  k[1] ^=  s[ k[14]  ];
  k[2] ^=  s[ k[15]  ];
  k[3] ^=  s[ k[12]  ];
}

void Attack::printState(const uint8_t state[16]){
  for(int i=0; i<16; i++){
      if(i%4 == 0)
        printf("\n");
    printf("%02X ", state[i]);
  }
  printf("\n");
}

#endif
