#ifndef __ATTACK_HPP
#define __ATTACK_HPP

#include <iostream>
#include <vector>
#include <cstring>
#include <gmpxx.h>
#include <fstream>
#include "montgomery.hpp"

using namespace std;

#define NORESULT -1
#define SUCCESS 0
#define ERROR1 1
#define ERROR2 2

class Attack {
  private:
    void Interact(mpz_class cypherText, mpz_class &plainText, mpz_class &time);
    void Initialise(int count);
    void throwErrorAndAbort(string errorMessage);
    bool Verify(mpz_class sk);
  public:
    Attack(ifstream& input, FILE* in, FILE* out);
    void Execute();
  private:
    mpz_class N, e, testMessage, rhoSquared;
    mp_limb_t omega;
    vector<mpz_class> sampleCyphers,sampleTimes,samplePlaintexts, temp_cs_0, temp_cs_1;
    mpz_class cypherVerify{4324585884327}, plaintextVerify;
    vector<bool> secretKey;
    mpz_class sk{1};
    gmp_randclass randomGenerator{gmp_randinit_default};
    Montgomery montgomeryInstance;
    FILE* target_in;
    FILE* target_out;
    unsigned long interactionCount;
};

Attack::Attack(ifstream& input, FILE* in, FILE* out) {
  string line;
  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", N);

  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", e);

  interactionCount = 0;

  target_in  = in;
  target_out = out;

  cypherVerify = mpz_class(4324585884327);
  mpz_class currTime(0);
  Interact(cypherVerify, plaintextVerify, currTime);
}

void Attack::Interact(mpz_class cypherText, mpz_class &plainText, mpz_class &currTime) {
  gmp_fprintf(target_in, "%0*ZX\n", mpz_sizeinbase(N.get_mpz_t(), 16), cypherText);
  fflush(target_in);

  int res = gmp_fscanf(target_out, "%Zd\n%ZX", currTime, plainText);
  if(res == 2) {
    interactionCount++;
  } else {
    throwErrorAndAbort("The target did not return the amount of information required.");
  }
}

void Attack::Initialise(int count) {
  omega = montgomeryInstance.GetOmega(N.get_mpz_t());
  montgomeryInstance.GetRhoSquared(rhoSquared.get_mpz_t(), N.get_mpz_t());

  for(int i = 0; i < count; i++) {
    mpz_class c    = randomGenerator.get_z_range(N);
    mpz_class time(0), plainText(0);
    Interact(c, plainText, time);

    montgomeryInstance.Convert(c.get_mpz_t(), c.get_mpz_t(), rhoSquared.get_mpz_t(), omega, N.get_mpz_t());
    sampleCyphers.push_back(c);
    sampleTimes.push_back(time);

    montgomeryInstance.Multiplication(c.get_mpz_t(), c.get_mpz_t(), c.get_mpz_t(), omega, N.get_mpz_t());
    temp_cs_1.push_back(c);
    temp_cs_0.push_back(0);
  }
  secretKey.clear();
  secretKey.push_back(true);
}

void Attack::throwErrorAndAbort(string errorMessage) {
  printf("here\n");
  cerr<<errorMessage<<endl;
  abort();
}

bool Attack::Verify(mpz_class sk) {
  mpz_class m;

  mpz_powm(m.get_mpz_t(), cypherVerify.get_mpz_t(), sk.get_mpz_t(), N.get_mpz_t());
  if(m == plaintextVerify){
    return true;
  } else {
    return false;
  }
}

void Attack::Execute() {
  Initialise(2000);
  while(!Verify(sk)) {
    mpz_class time1(0), time1red(0);
    int time1_count(0), time1red_count(0); // counters
    
    mpz_class time0(0), time0red(0);
    int time0_count(0), time0red_count(0); // counters

    for(int i = 0; i < sampleCyphers.size(); i++) {
      mpz_class curr, prev;
      mpz_class currentTime = sampleTimes[i];
      if(secretKey.back()) {
        //previous bit of the key is 1
        prev = temp_cs_1[i];
      } else {
        prev = temp_cs_0[i];
      }

      //last bit is 0 so square only
      montgomeryInstance.Multiplication(curr.get_mpz_t(), prev.get_mpz_t(), prev.get_mpz_t(), omega, N.get_mpz_t());
      if(curr >= N) {
        curr = curr % N;
        time0red += currentTime;
        time0red_count ++;
      } else {
        time0 += currentTime;
        time0_count ++;
      }

      temp_cs_0[i] = curr;

      montgomeryInstance.Multiplication(curr.get_mpz_t(), prev.get_mpz_t(), sampleCyphers[i].get_mpz_t(), omega, N.get_mpz_t());
      if(curr >= N) {
        curr = curr % N;
      }
      montgomeryInstance.Multiplication(curr.get_mpz_t(), curr.get_mpz_t(), curr.get_mpz_t(), omega, N.get_mpz_t());
      if(curr >= N) {
        curr = curr % N;
        time1red += currentTime;
        time1red_count ++;
      } else {
        time1 += currentTime;
        time1_count ++;
      }

      temp_cs_1[i] = curr;
    }

    if(time1_count != 0) {
      time1 = time1 / time1_count;
    }
    if(time0_count != 0) {
      time0 = time0 / time0_count;
    }
    if(time1red_count != 0) {
      time1red = time1red / time1red_count;
    }
    if(time0red_count != 0) {
      time0red = time0red / time0red_count;
    }

    mpz_class diff_0 = time0 - time0red;
    mpz_abs(diff_0.get_mpz_t(), diff_0.get_mpz_t());
    mpz_class diff_1 = time1 - time1red;
    mpz_abs(diff_1.get_mpz_t(), diff_1.get_mpz_t());
    if(diff_1 > diff_0) {
      //guess 1
      secretKey.push_back(1);
      sk = sk * 2 + 1;
    } else if(diff_1 < diff_0) {
      //guess 0
      secretKey.push_back(0);
      sk = sk * 2 + 0;
    } else {
      cout<<"can't distinguish this bit so add more samples"<<endl;
      Initialise(1000);
    }
    if(Verify(sk << 1)) {
      sk = sk << 1;
      break;
    }
    if(Verify((sk << 1) + 1)) {
      sk = (sk << 1) + 1;
      break;
    }
  }
  gmp_printf("The secret key is: %ZX\n", sk);
}

#endif