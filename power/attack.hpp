#ifndef __ATTACK_HPP
#define __ATTACK_HPP

#include <iostream>
#include <vector>
#include <iterator>
#include <cstring>
#include <gmpxx.h>
#include <fstream>
#include "params.hpp"
using namespace std;

/*
 * @brief Constants to describe the relevant error codes returned by the target.
 */

class Attack {
  private:
    FILE* target_in;
    FILE* target_out;
    unsigned long interactionCount;
    vector<mpz_class> messages;
    vector<vector<int>>powerTraces;
    gmp_randclass randomGenerator{gmp_randinit_default};
    int sampleCount;
    void (*cleanup)(int s);
  
  private:
    void AddMoreSamples();
    void Interact(int j, mpz_class i, mpz_class& m, vector<int>& power);
    void throwErrorAndAbort(string errorMessage);
  
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
  sampleCount = 0;

  target_in  = in;
  target_out = out;
  cleanup = clean;
}

/**
 * @brief Function to interact with the attack target
 *
 * @param block    integer value representing the block address
 * @param sector   octet string value representing the sector address or XTS-AES tweak
 * @param message  mpz_class value which will be set to the message obtained from the target Driver
 * @param power    the first 10% of the power trace for the given block and sector
 */
void Attack::Interact(int block, mpz_class sector, mpz_class& message, vector<int>& power) {
  gmp_fprintf(target_in, "%d\n", block);  
  gmp_fprintf(target_in, "%032ZX\n", sector.get_mpz_t());
  fflush(target_in);

  int length;
  gmp_fscanf(target_out, "%d", &length);
  power.resize(length / 10);
  for(int ind = 0; ind < length / 10; ind++){
    gmp_fscanf(target_out, ",%d", &power[ind]);
  }
  gmp_fscanf(target_out, "%*[^\n]");
  gmp_fscanf(target_out, "%ZX", message);
  interactionCount++;
}

/**
 * @brief Function which ads 20 more power trace samples.
 */
void Attack::AddMoreSamples(){
  powerTraces.resize(sampleCount + 20);
  messages.resize(sampleCount + 20);
  for(int i = sampleCount; i < sampleCount + 20; i++) {
    mpz_class sector(i); 
    mpz_class block = randomGenerator.get_z_range(256);
    mpz_class message;
    vector<int> currentTrace;
    Interact(block.get_si(), sector, message, currentTrace);
    powerTraces[i] = currentTrace;
    messages[i] = message;
  }
  sampleCount += 20;
}

/**
 * @brief Driver function which performs all the steps of the attack and prints any relevant output to stdout or sterr.
 */
void Attack::Execute() {
  AddMoreSamples(); 
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