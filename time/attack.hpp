#ifndef __ATTACK_HPP
#define __ATTACK_HPP

#include <iostream>
#include <vector>
#include <cstring>
#include <gmpxx.h>
#include <fstream>
#include "montgomery.hpp"

using namespace std;

class Attack {
  private:
    void Interact(mpz_class cypherText, mpz_class &plainText, mpz_class &time);
    void Initialise(int count);
    void throwErrorAndAbort(string errorMessage);
    bool Verify();
  public:
    Attack(ifstream& input, FILE* in, FILE* out, void (*clean)(int s));
    void Execute();
  private:
    mpz_class N, e, testMessage, rhoSquared;
    mp_limb_t omega;
    vector<mpz_class> sampleCyphers,sampleTimes,samplePlaintexts;
    vector<vector<mpz_class>> temp_cs_0, temp_cs_1;
    mpz_class cypherVerify{4324585884327}, plaintextVerify; //this is just a random value to use when checking the recovered key correctness
    vector<bool> secretKey;
    mpz_class sk;
    gmp_randclass randomGenerator{gmp_randinit_default};
    Montgomery montgomeryInstance;
    FILE* target_in;
    FILE* target_out;
    unsigned long interactionCount;
    void (*cleanup)(int s);
};

/**
 * @brief Constructor for the Attack Class.
 *
 * @param input  ifstream of the conf file.
 * @param in     pointer to the stdin of the target.
 * @param out    pointer to the stdout of the target.
 * @param clean  the cleanup function to be invoked on abnormal exit.
 */
Attack::Attack(ifstream& input, FILE* in, FILE* out, void (*clean)(int s)) {
  string line;
  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", N);

  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", e);

  interactionCount = 0;
  target_in  = in;
  target_out = out;
  cleanup = clean;

  mpz_class currTime(0);
  Interact(cypherVerify, plaintextVerify, currTime);
  omega = montgomeryInstance.GetOmega(N.get_mpz_t());
  montgomeryInstance.GetRhoSquared(rhoSquared.get_mpz_t(), N.get_mpz_t());
}

/**
 * @brief Function to interact with the attack target
 *        and which gets the time measurments needed.
 *
 * @param cypherText  the cyphertext to be decrypted.
 * @param plainText   will contain the plaintext obtained after decryption finishes.
 * @param currTime    will contain the time measured in clock cycles required for decryption.
 */
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

/**
 * @brief Function used to add more randomly sampled cyphertexts to the set of 
 *        cyphertexts used in the attack as well as to reset the value of the secret key.
 *
 * @param count  number of new cyphertexts to add to the existing set.
 */
void Attack::Initialise(int count) {
  for(int i = 0; i < count; i++) {
    mpz_class c    = randomGenerator.get_z_range(N);
    mpz_class time1(0), plainText(0);
    Interact(c, plainText, time1);

    montgomeryInstance.Convert(c.get_mpz_t(), c.get_mpz_t(), rhoSquared.get_mpz_t(), omega, N.get_mpz_t());
    sampleCyphers.push_back(c);
    sampleTimes.push_back(time1);

    montgomeryInstance.Multiplication(c.get_mpz_t(), c.get_mpz_t(), c.get_mpz_t(), omega, N.get_mpz_t());
    temp_cs_1[0].push_back(c);
    temp_cs_0[0].push_back(0);
  }
  secretKey.clear();
  secretKey.push_back(true);
  sk = 1;
}

/**
 * @brief Function used to check that the private key obtained is correct.
 *
 * @return true if the key is the real private key that corresponds to e and false otherwise.
 */
bool Attack::Verify() {
  mpz_class m;
  mpz_powm(m.get_mpz_t(), cypherVerify.get_mpz_t(), sk.get_mpz_t(), N.get_mpz_t());
  if(m == plaintextVerify){
    return true;
  } else {
    return false;
  }
}

/**
 * @brief Driver function which performs all the steps of the attack and prints any relevant output to stdout or sterr.
 */
void Attack::Execute() {
  /*
   * By running the 12862.R target using the test.cpp program i found that every operation multiplication takes 
   * aproximately 3770 clock cycles which I rounded down to 3700 to acount for possible noise in measurments with 
   * different parameters and therefore I use this value to estimate the number of operations that
   * take place when performing operations using this key.
   */
  unsigned long timePerOperation(3700), timeForSetBit(timePerOperation * 2);
  mpz_class c(0), m(0), timeForChallenge(0);
  Interact(c, m, timeForChallenge);

  /* This is the estimated number of multiplications performed using the private key during any decryption 
   * except the two accounting to the first bit in the key. I try to overestimate in order to account for
   * possible noise due to the reductions that may be performed during the computation.
   */
  mpz_class numOfOpsWithKey = (timeForChallenge - timeForSetBit);
  
  mpz_cdiv_q_ui(numOfOpsWithKey.get_mpz_t(), numOfOpsWithKey.get_mpz_t(), timePerOperation) ;
  temp_cs_0.resize(numOfOpsWithKey.get_ui());
  temp_cs_1.resize(numOfOpsWithKey.get_ui());
  gmp_printf("Estimated number of multiplications during decryption: %Zd\n", numOfOpsWithKey);
  mpz_class currentOpsPerformed(2);
  
  int currBit(1);
  bool backtracked(false);

  Initialise(2000);
  while(!Verify() && numOfOpsWithKey > currentOpsPerformed) {
    mpz_class time1(0), time1red(0);
    int time1_count(0), time1red_count(0); // counters
    
    mpz_class time0(0), time0red(0);
    int time0_count(0), time0red_count(0); // counters
    temp_cs_0[currBit].resize(sampleCyphers.size());
    temp_cs_1[currBit].resize(sampleCyphers.size());
    for(int i = 0; i < sampleCyphers.size(); i ++) {
      mpz_class curr, prev;
      mpz_class currentTime = sampleTimes[i];
      if(secretKey.back()) {
        //previous bit of the key is 1
        prev = temp_cs_1[currBit - 1][i];
      } else {
        prev = temp_cs_0[currBit - 1][i];
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
      temp_cs_0[currBit][i] = curr;

      //last bit is 1 so multiply then square
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
      temp_cs_1[currBit][i] = curr;
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
    mpz_class totalDiff = diff_0 - diff_1;
    mpz_abs(totalDiff.get_mpz_t(), totalDiff.get_mpz_t());
    if(totalDiff > 10) {
      if(diff_1 > diff_0) {
        //guess 1 so increase operations performed count by 2
        secretKey.push_back(1);
        sk = (sk << 1) + 1;
        currentOpsPerformed += 2;
      } else {
        //guess 0 so increase operations performed count by 1
        secretKey.push_back(0);
        sk = (sk << 1);
        currentOpsPerformed += 1;
      }
    } else {
      if(backtracked) {
        //resample if already backtracked
        cout<<"Resampling at bit: "<<currBit<<endl;
        Initialise(500);
        backtracked = false;
        currBit = 1;
        currentOpsPerformed = 2;
        secretKey.resize(1);
        continue;
      } else{
        //do the backtracking
        cout<<"Backtracking at bit: "<<currBit<<endl;
        currBit--;
        backtracked = true;
        if(secretKey.back()) {
          secretKey.pop_back();
          secretKey.push_back(0);
          currentOpsPerformed -= 1;
        } else {
          secretKey.pop_back();
          secretKey.push_back(1);
          currentOpsPerformed += 1;
        }
      }
    }
    
    sk = sk << 1;
    if(Verify()) {
      secretKey.push_back(0);
      currentOpsPerformed += 1;
      break;
    }

    sk += 1;
    if(Verify()) {
      secretKey.push_back(1);
      currentOpsPerformed += 2;
      break;
    }
    sk = (sk - 1) >> 1;
    currBit++;
  }
  gmp_printf("Actual number of arithmetic ops performed during a decryption: %Zd\n", currentOpsPerformed);
  cout<<endl<<endl<<"The binary representation of the secret key is:"<<endl;
  for(bool bit : secretKey) {
    cout<<bit;
  }
  gmp_printf("\nThe secret key is: %ZX\n", sk);
  cout<<"Number of interactions with the target is: "<<interactionCount<<endl;
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