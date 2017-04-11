#ifndef __ATTACK_HPP
#define __ATTACK_HPP

#include <iostream>
#include <vector>
#include <iterator>
#include <cstring>
#include <gmpxx.h>
#include <fstream>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

using namespace std;

/*
 * @brief Constants to describe the relevant error codes returned by the target.
 */
#define NORESULT -1
#define SUCCESS 0
#define ERROR1 1
#define ERROR2 2

class Attack {
  private:
    FILE* target_in;
    FILE* target_out;
    unsigned long interactionCount;
    void (*cleanup)(int s);
  
  private:
    int Interact();
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

  target_in  = in;
  target_out = out;
  cleanup = clean;
}

/**
 * @brief Function to interact with the attack target
 *        corresponding to the oracle queries in Manger's paper.
 *
 * @param f is an mpz_class object used to calculate (f^e) * c (mod N) which is the query to the oracle.
 */
int Attack::Interact() {
  throwErrorAndAbort("No error code returned from the Oracle!");  
}

/**
 * @brief Driver function which performs all the steps of the attack and prints any relevant output to stdout or sterr.
 */
void Attack::Execute() {
  cout<<"Hello WORLD"<<endl;
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