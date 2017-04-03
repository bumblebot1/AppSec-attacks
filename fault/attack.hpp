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
    vector<byte> MPZ_to_vector(const mpz_t x); 
    void Step1(vector<byte> &x, 
               vector<byte> &x_faulty,
               vector<byte> &k, 
               vector<vector<byte>> &k_1, 
               vector<vector<byte>> &k_2, 
               vector<vector<byte>> &k_3, 
               int ind0, int ind1, int ind2, int ind3);
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
 * @brief Converts and mpz_t number into an little endian array of bytes (most significant byte last)
 *
 * @param x   an mpz_t number to be converted
 *
 * @return vector<byte> representing x as a byte array in little endian form
 */
vector<byte> Attack::MPZ_to_vector(const mpz_t x) {
  size_t size = (mpz_sizeinbase (x, 2) + CHAR_BIT-1) / CHAR_BIT;
  vector<byte> v(size);
  mpz_export(v.data(), &size, 1, 1, 0, 0, x);
  v.resize(size);
  return v;
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

void Attack::Execute() {
  m = randomGenerator.get_z_bits(128);
  Interact("", m, c);
  Interact("8,1,0,0,0", m, c_faulty);
  vector<byte> x, x_faulty;
  x = MPZ_to_vector(c.get_mpz_t());
  x_faulty = MPZ_to_vector(c_faulty.get_mpz_t());
  
  vector<byte> k10, k1, k8, k3;
  vector<vector<byte>>k0, k2, k4, k5, k6, k7, k9, k11, k12, k13, k14, k15;
  Step1(x, x_faulty, k10, k13, k0,  k7,  10, 13, 0,  7);
  Step1(x, x_faulty, k1,  k4,  k11, k14, 1,  4,  11, 14);
  Step1(x, x_faulty, k8,  k15, k2,  k5,  8,  15, 2,  5);
  Step1(x, x_faulty, k3,  k6,  k9,  k12, 3,  6,  9,  12);
}


void Attack::Step1(vector<byte> &x, 
                   vector<byte> &x_faulty, 
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
      if(MultiplicationTables[2][delta] == (SubBytesInverse[x[ind2] ^ byte2] ^ SubBytesInverse[x_faulty[ind2] ^ byte2]))
        k_2_vect.push_back(byte2);
    }
    if (k_2_vect.empty())
      continue;
    
    for (int j = 0; j < 256; j++) {
      byte byte3 = j;
      if(MultiplicationTables[3][delta] == (SubBytesInverse[x[ind3] ^ byte3] ^ SubBytesInverse[x_faulty[ind3] ^ byte3]))
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