#ifndef __ATTACK_HPP
#define __ATTACK_HPP

#include  <cstdio>
#include  <cstdlib>
#include  <iostream>
#include  <cstring>
#include  <signal.h>
#include  <unistd.h>
#include  <fcntl.h>
#include  <gmpxx.h>
#include  <fstream>
#include  <openssl/sha.h>
#include  <openssl/evp.h>
#include  <openssl/rsa.h>

class Attack {
  private:
    mpz_class N, e, label, c;
    unsigned long interactionCount;
  
  public:
    Attack(std::ifstream& input);
    void printAll();
};

#endif