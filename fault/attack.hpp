#ifndef __ATTACK_HPP
#define __ATTACK_HPP

#include <iostream>
#include <iomanip>
#include <vector>
#include <iterator>
#include <cstring>
#include <gmpxx.h>
#include <fstream>
#include "aes_params.hpp"
#include "galois_multiples.hpp"
#include <omp.h>
#include <openssl/aes.h>

using namespace std;

typedef unsigned char byte;

class Attack {
  private:
    mpz_class m, c, c_faulty;
    FILE* target_in;
    FILE* target_out;
    unsigned long interactionCount;
    gmp_randclass randomGenerator{gmp_randinit_default};
    void (*cleanup)(int s);
  private:
    void throwErrorAndAbort(string errorMessage);
    unsigned char ComputeFPrime (unsigned char x[], unsigned char x_faulty[], vector<unsigned char> &r, vector<unsigned char> &k);
    unsigned char ComputeFPrime1(unsigned char x[], unsigned char x_faulty[], vector<unsigned char> &r, vector<unsigned char> &k);
    unsigned char ComputeFPrime2(unsigned char x[], unsigned char x_faulty[], vector<unsigned char> &r, vector<unsigned char> &k);
    unsigned char ComputeFPrime3(unsigned char x[], unsigned char x_faulty[], vector<unsigned char> &r, vector<unsigned char> &k);
    void Step1(unsigned char x[16], 
               unsigned char x_faulty[16],
               vector<byte> &k, 
               vector<vector<byte>> &k_1, 
               vector<vector<byte>> &k_2, 
               vector<vector<byte>> &k_3, 
               int ind0, int ind1, int ind2, int ind3);
    void KeyInv(unsigned char* r, const unsigned char* k, int round);
    void Interact(string fault, mpz_class &m, mpz_class &c);
  public:
    Attack(FILE* in, FILE* out, void (*clean)(int s));
    void Execute();
};

/**
 * @brief Constructor for the Attack Class.
 *
 * @param in     pointer to the stdin of the target.
 * @param out    pointer to the stdout of the target.
 * @param clean  the cleanup function to be invoked on abnormal exit.
 */
Attack::Attack(FILE* in, FILE* out, void (*clean)(int s)) {
  interactionCount = 0;

  target_in  = in;
  target_out = out;
  cleanup = clean;
}

/*
 * @brief function to interact with the attack target
 *
 * @param fault    string specifying the fault to be induced
 * @param m        mpz_class message to be encrypted by the target
 * @param c        mpz_class value to hold the cyphertext corresponding to the faulty encryption of m
 */
void Attack::Interact(string fault, mpz_class &m, mpz_class &c)
{
  gmp_fprintf(target_in, "%s\n%ZX\n", fault.c_str(), m.get_mpz_t());
  fflush(target_in);

  gmp_fscanf(target_out, "%ZX", c.get_mpz_t());
  interactionCount++;
}

void Attack::KeyInv(unsigned char* r, const unsigned char* k, int round) {
    unsigned char round_char = Rcon[round];
    r[15] = k[15] ^ k[11];
    r[14] = k[14] ^ k[10];
    r[13] = k[13] ^ k[9];
    r[12] = k[12] ^ k[8];
    
    r[11] = k[11] ^ k[7];
    r[10] = k[10] ^ k[6];
    r[9]  =  k[9] ^ k[5];
    r[8]  =  k[8] ^ k[4];
    
    r[7]  =  k[7] ^ k[3];
    r[6]  =  k[6] ^ k[2];
    r[5]  =  k[5] ^ k[1];
    r[4]  =  k[4] ^ k[0];
    
    r[3]  = SubBytes[r[12]] ^ k[3];
    r[2]  = SubBytes[r[15]] ^ k[2];
    r[1]  = SubBytes[r[14]] ^ k[1];
    r[0]  = SubBytes[r[13]] ^ k[0] ^ round_char;    
}

void Attack::Execute() {
  m = randomGenerator.get_z_bits(128);
  Interact("", m, c);
  Interact("8,1,0,0,0", m, c_faulty);
  unsigned char x[16], x_faulty[16];
  mpz_export(x, NULL, 1, 1, 0, 0, c.get_mpz_t());
  mpz_export(x_faulty, NULL, 1, 1, 0, 0, c_faulty.get_mpz_t());
  
  vector<byte> k10, k1, k8, k3;
  vector<vector<byte>>k0, k2, k4, k5, k6, k7, k9, k11, k12, k13, k14, k15;
  Step1(x, x_faulty, k10, k13, k0,  k7,  10, 13, 0,  7);
  Step1(x, x_faulty, k1,  k4,  k11, k14, 1,  4,  11, 14);
  Step1(x, x_faulty, k8,  k15, k2,  k5,  8,  15, 2,  5);
  Step1(x, x_faulty, k3,  k6,  k9,  k12, 3,  6,  9,  12);

  unsigned char m_char[16] = {0};
  unsigned char c_char[16] = {0};
  mpz_export(m_char, NULL, 1, 1, 0, 0, m.get_mpz_t());
  mpz_export(c_char, NULL, 1, 1, 0, 0, c.get_mpz_t());

  #pragma omp parallel for
  for (int i_10 = 0 ; i_10 < k10.size(); i_10++) {   // each hypothesis for 10th key byte
    for (unsigned char byte_13 : k13[i_10])       // each respective hypothesis for 13th key byte
    for (unsigned char byte_0 : k0[i_10])     // each respective hypothesis for  0th key byte
    for (unsigned char byte_7 : k7[i_10]) // each respective hypothesis for  7th key byte
      
      for (int i_1 = 0 ; i_1 < k1.size(); i_1++)       // each hypothesis for 1st key byte
      for (unsigned char byte_4 : k4[i_1])          // each respective hypothesis for  4th key byte
      for (unsigned char byte_11 : k11[i_1])    // each respective hypothesis for 11th key byte
      for (unsigned char byte_14 : k14[i_1])// each respective hypothesis for 14th key byte
                      
        for (int i_8 = 0; i_8 < k8.size(); i_8++)      // each hypothesis for 8th key byte
        for (unsigned char byte_15 : k15[i_8])      // each respective hypothesis for 15th key byte
        for (unsigned char byte_2 : k2[i_8])    // each respective hypothesis for  2nd key byte
        for (unsigned char byte_5 : k5[i_8])// each respective hypothesis for  5th key byte
                                                  
          for (int i_3 = 0; i_3 < k3.size(); i_3++)        // each hypothesis for 3rd key byte
          for (unsigned char byte_6 : k6[i_3])          // each respective hypothesis for  6th key byte
          for (unsigned char byte_9 : k9[i_3])      // each respective hypothesis for  9th key byte
          for (unsigned char byte_12 : k12[i_3]) { // each respective hypothesis for 12th key byte
              // 'assemble' the hypothetical key
              vector<unsigned char> key(16);
              key[0] = byte_0;
              key[1] = k1[i_1];
              key[2] = byte_2;
              key[3] = k3[i_3];
              key[4] = byte_4;
              key[5] = byte_5;
              key[6] = byte_6;
              key[7] = byte_7;
              key[8] = k8[i_8];
              key[9] = byte_9;
              key[10] = k10[i_10];
              key[11] = byte_11;
              key[12] = byte_12;
              key[13] = byte_13;
              key[14] = byte_14;
              key[15] = byte_15;
              
              vector<unsigned char> inv_key(16);
              
              // inverse the hypothetical key: to get 9th round key
              KeyInv(inv_key.data(), key.data(), 10);
              
              // second step of the attack
              unsigned char f_prime = ComputeFPrime(x, x_faulty, inv_key, key);
              if (f_prime != ComputeFPrime1(x, x_faulty, inv_key, key))
                  continue;
              if (GaloisTable3[f_prime] != ComputeFPrime3(x, x_faulty, inv_key, key))
                  continue;
              if (GaloisTable2[f_prime] != ComputeFPrime2(x, x_faulty, inv_key, key))
                  continue;
              cout<<"."<<flush;
              // get the AES key from the 10th round key
              for (int j = 10; j > 0; j--)
                  KeyInv(key.data(), key.data(), j);
              
              // verification step
              unsigned char t[16];

              AES_KEY rk;
              AES_set_encrypt_key(key.data(), 128, &rk);
              AES_encrypt(m_char, t, &rk);  

              if(!memcmp(t, c_char, 16)) {
                  printf("\nAES.Enc( k, m ) == c\nk = ");
                  for (int i = 0; i < 16; i++)
                      printf("%02X", key[i]);
                  
                  cout << "\nNumber of interactions with the target: " << interactionCount << "\n\n";
                  exit(0);
              }   
          }
  }
}


void Attack::Step1(unsigned char x[16], 
                   unsigned char x_faulty[16], 
                   vector<byte> &k, 
                   vector<vector<byte>> &k_1, 
                   vector<vector<byte>> &k_2, 
                   vector<vector<byte>> &k_3, 
                   int ind0, int ind1, int ind2, int ind3) {
  for (int i = 0; i < 256; i++) {
    byte byte0 = i;

    byte delta = (SubBytesInverse[x[ind0] ^ byte0] ^ SubBytesInverse[x_faulty[ind0] ^ byte0]);
    vector<byte> k_1_vect, k_2_vect, k_3_vect;

    for (int j = 0; j < 256; j++) {
      byte byte1 = j;
      if(delta == (SubBytesInverse[x[ind1] ^ byte1] ^ SubBytesInverse[x_faulty[ind1] ^ byte1]))
        k_1_vect.push_back(byte1);
    }
    if (k_1_vect.empty())
      continue;

    for (int j = 0; j < 256; j++) {
      byte byte2 = j;
      if(GaloisTable2[delta] == (SubBytesInverse[x[ind2] ^ byte2] ^ SubBytesInverse[x_faulty[ind2] ^ byte2]))
        k_2_vect.push_back(byte2);
    }
    if (k_2_vect.empty())
      continue;
    
    for (int j = 0; j < 256; j++) {
      byte byte3 = j;
      if(GaloisTable3[delta] == (SubBytesInverse[x[ind3] ^ byte3] ^ SubBytesInverse[x_faulty[ind3] ^ byte3]))
        k_3_vect.push_back(byte3);
    }
    if (k_3_vect.empty())
      continue;

    k.push_back(byte0);
    k_1.push_back(k_1_vect);
    k_2.push_back(k_2_vect);
    k_3.push_back(k_3_vect);
  }
}

unsigned char Attack::ComputeFPrime(unsigned char x[], unsigned char x_faulty[], vector<unsigned char> &r, vector<unsigned char> &k) {
    unsigned char A = SubBytesInverse[
                        GaloisTable9[SubBytesInverse[x[12]^k[12]] ^ r[12]] ^
                        GaloisTable14[SubBytesInverse[x[9] ^k[9] ] ^ r[13]] ^
                        GaloisTable11[SubBytesInverse[x[6] ^k[6] ] ^ r[14]] ^
                        GaloisTable13[SubBytesInverse[x[3] ^k[3] ] ^ r[15]] 
                      ];
    unsigned char B = SubBytesInverse[
                        GaloisTable9[SubBytesInverse[x_faulty[12]^k[12]] ^ r[12]] ^
                        GaloisTable14[SubBytesInverse[x_faulty[9] ^k[9] ] ^ r[13]] ^
                        GaloisTable11[SubBytesInverse[x_faulty[6] ^k[6] ] ^ r[14]] ^
                        GaloisTable13[SubBytesInverse[x_faulty[3] ^k[3] ] ^ r[15]] 
                      ];
    return (A ^ B);
}

unsigned char Attack::ComputeFPrime1(unsigned char x[], unsigned char x_faulty[], vector<unsigned char> &r, vector<unsigned char> &k) {
    unsigned char A = SubBytesInverse[
                        GaloisTable9[SubBytesInverse[x[5] ^k[5] ] ^  r[9]] ^
                        GaloisTable14[SubBytesInverse[x[2] ^k[2] ] ^ r[10]] ^
                        GaloisTable11[SubBytesInverse[x[15]^k[15]] ^ r[11]] ^
                        GaloisTable13[SubBytesInverse[x[8] ^k[8] ] ^  r[8]] 
                      ];
    unsigned char B = SubBytesInverse[
                        GaloisTable9[SubBytesInverse[x_faulty[5] ^k[5] ] ^  r[9]] ^
                        GaloisTable14[SubBytesInverse[x_faulty[2] ^k[2] ] ^ r[10]] ^
                        GaloisTable11[SubBytesInverse[x_faulty[15]^k[15]] ^ r[11]] ^
                        GaloisTable13[SubBytesInverse[x_faulty[8] ^k[8] ] ^  r[8]] 
                      ];
    return (A ^ B);
}

unsigned char Attack::ComputeFPrime2(unsigned char x[], unsigned char x_faulty[], vector<unsigned char> &r, vector<unsigned char> &k) {
    unsigned char A = SubBytesInverse[
                        GaloisTable9[SubBytesInverse[x[7] ^k[7] ] ^ r[3]] ^
                        GaloisTable14[SubBytesInverse[x[0] ^k[0] ] ^ r[0]] ^
                        GaloisTable11[SubBytesInverse[x[13]^k[13]] ^ r[1]] ^
                        GaloisTable13[SubBytesInverse[x[10]^k[10]] ^ r[2]] 
                      ];
    unsigned char B = SubBytesInverse[
                        GaloisTable9[SubBytesInverse[x_faulty[7] ^k[7] ] ^ r[3]] ^
                        GaloisTable14[SubBytesInverse[x_faulty[0] ^k[0] ] ^ r[0]] ^
                        GaloisTable11[SubBytesInverse[x_faulty[13]^k[13]] ^ r[1]] ^
                        GaloisTable13[SubBytesInverse[x_faulty[10]^k[10]] ^ r[2]] 
                      ];
    return (A ^ B);
}

unsigned char Attack::ComputeFPrime3(unsigned char x[], unsigned char x_faulty[], vector<unsigned char> &r, vector<unsigned char> &k) {
    unsigned char A = SubBytesInverse[
                        GaloisTable9[SubBytesInverse[x[14]^k[14]] ^ r[6]] ^
                        GaloisTable14[SubBytesInverse[x[11]^k[11]] ^ r[7]] ^
                        GaloisTable11[SubBytesInverse[x[4] ^k[4] ] ^ r[4]] ^
                        GaloisTable13[SubBytesInverse[x[1] ^k[1] ] ^ r[5]] 
                      ];    
    unsigned char B = SubBytesInverse[
                        GaloisTable9[SubBytesInverse[x_faulty[14]^k[14]] ^ r[6]] ^
                        GaloisTable14[SubBytesInverse[x_faulty[11]^k[11]] ^ r[7]] ^
                        GaloisTable11[SubBytesInverse[x_faulty[4] ^k[4] ] ^ r[4]] ^
                        GaloisTable13[SubBytesInverse[x_faulty[1] ^k[1] ] ^ r[5]] 
                      ];
    return (A ^ B);
}
/**
 * @brief Function which aborts execution and prints an error message to stderr.
 *
 * @param errorMessage  the error message to be printed to stderr
 */
void Attack::throwErrorAndAbort(string errorMessage) {
  cerr<<errorMessage<<endl;
  cleanup(-1);
}

#endif