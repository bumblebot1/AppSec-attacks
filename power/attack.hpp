#ifndef __ATTACK_HPP
#define __ATTACK_HPP

#include <iostream>
#include <vector>
#include <iterator>
#include <cstring>
#include <gmpxx.h>
#include <fstream>
#include <openssl/aes.h>
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
    vector<mpz_class> messagesPhase2;
    vector<vector<int>>powerTraces;
    vector<vector<int>>powerTracesPhase2;
    int sampleCount;
    void (*cleanup)(int s);
  
  private:
    void AddMoreSamples();
    void Interact(int block, mpz_class sector, mpz_class& message, vector<int>& power, vector<int>& powerPhase2);
    float Mean(vector<int> trace);
    vector<unsigned char> Phase1();
    vector<unsigned char> Phase2();
    float PearsonCorr(vector<int> x, vector<int> y);
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
void Attack::Interact(int block, mpz_class sector, mpz_class& message, vector<int>& power, vector<int>& powerPhase2) {
  gmp_fprintf(target_in, "%d\n", block);  
  gmp_fprintf(target_in, "%032ZX\n", sector.get_mpz_t());
  fflush(target_in);

  int length;
  gmp_fscanf(target_out, "%d", &length);
  power.resize(length / 10);
  powerPhase2.resize(length / 10);
  int ind = 0;
  for(; ind < length / 10; ind++){
    gmp_fscanf(target_out, ",%d", &power[ind]);
  }
  while(ind < length/2) {
    int val;
    gmp_fscanf(target_out, ",%d", &val);
    ind++;
  }
  int k = 0;
  for(; ind < length/2 + length/10; ind++){
    gmp_fscanf(target_out, ",%d", &powerPhase2[k++]);
  }
  
  gmp_fscanf(target_out, "%*[^\n]");
  gmp_fscanf(target_out, "%ZX", message);
  interactionCount++;
}

/**
 * @brief Function which ads 20 more power trace samples.
 */
void Attack::AddMoreSamples(){
  powerTraces.resize(sampleCount + 100);
  messages.resize(sampleCount + 100);
  powerTracesPhase2.resize(sampleCount + 100);
  for(int i = sampleCount; i < sampleCount + 100; i++) {
    mpz_class sector(i); 
    mpz_class message;
    vector<int> currentTrace;
    vector<int> currentTracePhase2;
    Interact(0, sector, message, currentTrace, currentTracePhase2);
    powerTraces[i] = currentTrace;
    powerTracesPhase2[i] = currentTracePhase2;
    messages[i] = message;
  }
  sampleCount += 100;
}

float Attack::Mean(vector<int> trace) {
  float sum = 0;
  for(auto t : trace) {
    sum += t;
  }
  if(trace.size() != 0) {
    return (float) sum / trace.size();
  } else {
    return 0;
  }
}

float Attack::PearsonCorr(vector<int> x, vector<int> y) {
  float cov_xy(0), sum_x(0), sum_y(0);
  float meanX = Mean(x);
  float meanY = Mean(y);

  for (int i = 0; i < x.size(); i++) {
    cov_xy += (x[i] - meanX) * (y[i] - meanY);
    sum_x  += (x[i] - meanX) * (x[i] - meanX);    
    sum_y  += (y[i] - meanY) * (y[i] - meanY);
  }
  
  return (float) cov_xy / (sqrt(sum_x) * sqrt(sum_y));
}

/**
 * @brief Driver function which performs all the steps of the attack and prints any relevant output to stdout or sterr.
 */
void Attack::Execute() {
  AddMoreSamples();
  Phase1();
  Phase2();
}

vector<unsigned char> Attack::Phase2() {
  int minLen = powerTracesPhase2[0].size();
  for(int i = 1; i < powerTracesPhase2.size(); i++) {
    if(powerTracesPhase2[i].size() < minLen) {
      minLen = powerTracesPhase2[i].size();
    }
  }
  vector<vector<int>> powerMatrix(minLen, vector<int> (powerTracesPhase2.size()));
  for(int i = 0; i < minLen; i++) {
    for(int j = 0; j < powerTracesPhase2.size(); j++) {
      powerMatrix[i][j] = powerTracesPhase2[j][i];
    }
  }

  vector<unsigned char> key1(16);
  
  //recover each byte of the key individually
  #pragma omp parallel for
  for(int n = 0; n < 16; n++) {
    vector<vector<int>> simulatedTraces(256, vector<int>(messagesPhase2.size()));
    for(int i = 0; i < messagesPhase2.size(); i++) {
      mpz_class msg = messagesPhase2[i] >> (8 * n);
      //get the byte from the message which corresponds to the key byte we are recovering
      int byte = msg.get_si() & 0xff;
      for(int k = 0; k < 256; k++) {
        simulatedTraces[k][i] = HammingWeight[SubBytes[byte ^ k]];
      }
    }

    //calculate correlation between trace samples and our model
    vector<vector<float>>correlation(256, vector<float> (powerMatrix.size()));
    for(int i = 0; i < 256; i++) {
      for(int j = 0; j < powerMatrix.size(); j++) {
        if(powerMatrix[j].size() == simulatedTraces[i].size()) {
          correlation[i][j] = PearsonCorr(simulatedTraces[i], powerMatrix[j]);
        }
      }
    }

    float maxCorr = -2;
    int bestByte = -1;
    for(int i = 0; i < 256; i++) {
      for(int j = 0; j < powerMatrix.size(); j++) {
        if(abs(correlation[i][j]) > maxCorr) {
          maxCorr = abs(correlation[i][j]);
          bestByte = i;
        }
      }
    }
    key1[n] = bestByte;
  }
  for(int n = 15; n >= 0; n--){
    printf("%02X", (int)key1[n]);
  }
  cout<<endl;
  return key1;
}

vector<unsigned char> Attack::Phase1() {
  int minLen = powerTraces[0].size();
  for(int i = 1; i < powerTraces.size(); i++) {
    if(powerTraces[i].size() < minLen) {
      minLen = powerTraces[i].size();
    }
  }
  vector<vector<int>> powerMatrix(minLen, vector<int> (powerTraces.size()));
  for(int i = 0; i < minLen; i++) {
    for(int j = 0; j < powerTraces.size(); j++) {
      powerMatrix[i][j] = powerTraces[j][i];
    }
  }

  vector<unsigned char> key2(16);
  
  //recover each byte of the key individually
  #pragma omp parallel for
  for(int n = 0; n < 16; n++) {
    vector<vector<int>> simulatedTraces(256, vector<int>(messages.size()));
    for(int i = 0; i < messages.size(); i++) {
      mpz_class msg = messages[i] >> (8 * n);
      //get the byte from the message which corresponds to the key byte we are recovering
      int byte = msg.get_si() & 0xff;
      for(int k = 0; k < 256; k++) {
        simulatedTraces[k][i] = HammingWeight[SubBytes[byte ^ k]];
      }
    }

    //calculate correlation between trace samples and our model
    vector<vector<float>>correlation(256, vector<float> (powerMatrix.size()));
    for(int i = 0; i < 256; i++) {
      for(int j = 0; j < powerMatrix.size(); j++) {
        if(powerMatrix[j].size() == simulatedTraces[i].size()) {
          correlation[i][j] = PearsonCorr(simulatedTraces[i], powerMatrix[j]);
        }
      }
    }

    float maxCorr = -2;
    int bestByte = -1;
    for(int i = 0; i < 256; i++) {
      for(int j = 0; j < powerMatrix.size(); j++) {
        if(abs(correlation[i][j]) > maxCorr) {
          maxCorr = abs(correlation[i][j]);
          bestByte = i;
        }
      }
    }
    key2[n] = bestByte;
  }
  for(int n = 15; n >= 0; n--){
    printf("%02X", (int)key2[n]);
  }
  cout<<endl;

  messagesPhase2.resize(messages.size());
  for(int i = 0; i < messages.size(); i++) {
    mpz_class sector(i);
    unsigned char m_char[16] = {0}, t[16] = {0};
    mpz_export(m_char, NULL, 1, 1, 0, 0, sector.get_mpz_t());
    AES_KEY rk;
    AES_set_encrypt_key(key2.data(), 128, &rk);
    AES_encrypt(m_char, t, &rk);
    mpz_class nextPlaintext;
    mpz_import(nextPlaintext.get_mpz_t(), 16, 1, 1, 0, 0, t);      
    messagesPhase2[i] = nextPlaintext;
    i++;
  }
  return key2;
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