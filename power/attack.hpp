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
#define minSample 20
#define traceSize 5000

class Attack {
  private:
    FILE* target_in;
    FILE* target_out;
    unsigned long interactionCount;
    vector<mpz_class> messages;
    vector<mpz_class> sectorsPhase2;
    vector<mpz_class> messagesPhase2;
    vector<mpz_class> tweaks;
    vector<vector<int>>powerTraces;
    vector<vector<int>>powerTracesPhase2;
    gmp_randclass randomGenerator{gmp_randinit_default};
    mpz_class maxSector = 16777216;
    int sampleCount;
    int sampleCountPhase2;
    void (*cleanup)(int s);
  
  private:
    void AddMoreSamples();
    void SamplePart2();
    bool TestKey(vector<unsigned char> key1, vector<unsigned char> key2);
    void Interact(int block, mpz_class sector, mpz_class& message, vector<int>& power, vector<int>& powerPhase2);
    float Mean(vector<int> trace);
    vector<unsigned char> Phase1();
    vector<unsigned char> Phase2();
    double PearsonCorr(vector<int> x, vector<int> y);
    void throwErrorAndAbort(string errorMessage);
  
  public:
    Attack(FILE* in, FILE* out, void (*clean)(int s));
    void Execute();
};

Attack::Attack(FILE* in, FILE* out, void (*clean)(int s)) {
  interactionCount = 0;
  sampleCount      = 0;

  target_in        = in;
  target_out       = out;
  cleanup          = clean;
}

void Attack::Interact(int block, mpz_class sector, mpz_class& message, vector<int>& power, vector<int>& powerPhase2) {
  gmp_fprintf(target_in, "%d\n", block);  
  unsigned char m_char[16] = {0};
  mpz_export(m_char, NULL, 1, 1, 0, 0, sector.get_mpz_t());
  for(int i = 0; i < 16; i++){
   gmp_fprintf(target_in, "%02X", m_char[i]);
  }
  gmp_fprintf(target_in, "\n");
  fflush(target_in);

  int length;
  gmp_fscanf(target_out, "%d", &length);
  power.resize(traceSize);
  powerPhase2.resize(traceSize);
  int ind;
  int val;
  for(ind = 0; ind < length / 2; ind++){
    gmp_fscanf(target_out, ",%d", &val);
    if(ind < traceSize){
      power[ind] = val;
    }
  }
  int k = 0;
  for(; ind < length; ind++){
    gmp_fscanf(target_out, ",%d", &val);
    if(ind >= length - traceSize){
      powerPhase2[k++] = val;
    }
  }
  
  gmp_fscanf(target_out, "%ZX", message.get_mpz_t());
  interactionCount++;
}

void Attack::AddMoreSamples(){
  powerTraces.resize(sampleCount + minSample);
  tweaks.resize(sampleCount + minSample);
  for(int i = sampleCount; i < sampleCount + minSample; i++) {
    mpz_class sector = randomGenerator.get_z_bits(128);
    tweaks[i] = sector; 
    mpz_class message;
    vector<int> currentTrace;
    vector<int> currentTracePhase2;
    Interact(0, sector, message, currentTrace, currentTracePhase2);
    powerTraces[i] = currentTrace;
  }
  sampleCount += minSample;
}

void Attack::SamplePart2() {
  powerTracesPhase2.resize(sampleCountPhase2 + minSample);
  messages.resize(sampleCountPhase2 + minSample);
  messagesPhase2.resize(sampleCountPhase2 + minSample);
  sectorsPhase2.resize(sampleCountPhase2 + minSample);
  for(int i = sampleCountPhase2; i < sampleCountPhase2 + minSample; i++) {
      mpz_class sector = randomGenerator.get_z_range(maxSector);
      sectorsPhase2[i] = sector;
      mpz_class message;
      vector<int> currentTrace;
      vector<int> currentTracePhase2;
      Interact(0, sector, message, currentTrace, currentTracePhase2);
      powerTracesPhase2[i] = currentTracePhase2;
      messages[i] = message;
  }
  sampleCountPhase2 += minSample;
}

float Attack::Mean(vector<int> trace) {
  float sum = 0;
  for(int t : trace) {
    sum += (float)t;
  }
  if(trace.size() != 0) {
    return ((float) sum) / trace.size();
  } else {
    return 0;
  }
}

double Attack::PearsonCorr(vector<int> x, vector<int> y){
  double xMean=0, yMean=0;

  // compute mean of x
  for(int i=0; i<sampleCount; i++){
    xMean += x[i];
    yMean += y[i];
  }
  xMean = xMean/sampleCount;
  yMean = yMean/sampleCount;

  double top=0;
  double sx = 0, sy = 0, sx2 = 0, sy2 = 0;
  for(int i=0; i<sampleCount; i++){
    sx = (x[i]-xMean);
    sy = (y[i]-yMean);
    top += sx * sy;
    sx2 += sx*sx;
    sy2 += sy*sy;
  }
  double check = sqrt(sx2*sy2);
  if(check != 0 )
    return top/check;
  else{
    return 0;
  }
}

void Attack::Execute() {
  vector<unsigned char> key1, key2;
  int attempts = 0;
  do{
    AddMoreSamples();
    key2 = Phase1();
    sampleCountPhase2 = 0;
    int tries = 5;
    do{
      SamplePart2();
      cout<<sampleCountPhase2<<endl;
      for(int i = 0; i < messages.size(); i++) {
        mpz_class sector = sectorsPhase2[i];
        unsigned char m_char[16] = {0}, t[16] = {0};
        mpz_export(m_char, NULL, 1, 1, 1, 0, sector.get_mpz_t());
        AES_KEY rk;
        AES_set_encrypt_key(key2.data(), 128, &rk);
        AES_encrypt(m_char, t, &rk);
        mpz_class T;
        mpz_import(T.get_mpz_t(), 16, 1, 1, 1, 0, t);      
        messagesPhase2[i] = T ^ messages[i];
      }
      key1 = Phase2();
      tries--;
    } while(!TestKey(key1, key2) && tries > 0);

    attempts ++;
    gmp_printf("Resetting\n\n");
  } while(attempts < 10);
  gmp_printf("FAILED\n");
}

vector<unsigned char> Attack::Phase1() {
  vector<vector<int>> powerMatrix(traceSize, vector<int> (sampleCount));
  for(int i = 0; i < traceSize; i++) {
    for(int j = 0; j < sampleCount; j++) {
      powerMatrix[i][j] = powerTraces[j][i];
    }
  }
  vector<unsigned char> key2(16);
  
  //recover each byte of the key individually
  #pragma omp parallel for
  for(int n = 0; n < 16; n++) {
    vector<vector<int>> simulatedTraces(256, vector<int>(sampleCount));
    for(int i = 0; i < sampleCount; i++) {
      mpz_class msg = tweaks[i] >> (8 * n);
      //get the byte from the message which corresponds to the key byte we are recovering
      int byte = msg.get_si() & 0xff;
      for(int k = 0; k < 256; k++) {
        simulatedTraces[k][i] = HammingWeight[SubBytes[byte ^ k]];
      }
    }

    //calculate correlation between trace samples and our model
    vector<vector<double>>correlation(256, vector<double> (traceSize));
    for(int i = 0; i < 256; i++) {
      for(int j = 0; j < traceSize; j++) {
        correlation[i][j] = PearsonCorr(simulatedTraces[i], powerMatrix[j]);
      }
    }

    double maxCorr = -2;
    int bestByte = -1;
    for(int i = 0; i < 256; i++) {
      for(int j = 0; j < traceSize; j++) {
        if(correlation[i][j] > maxCorr) {
          maxCorr = correlation[i][j];
          bestByte = i;
        }
      }
    }
    key2[15 - n] = bestByte;
  }
  printf("Value of Key 2 is:");
  for(int n = 0; n < 16; n++){
    printf("%02X", (int)key2[n]);
  }
  printf("\n");

  return key2;
}

vector<unsigned char> Attack::Phase2(){
  vector<vector<int>> powerMatrix(traceSize, vector<int> (sampleCountPhase2));
  for(int i = 0; i < traceSize; i++) {
    for(int j = 0; j < sampleCountPhase2; j++) {
      powerMatrix[i][j] = powerTracesPhase2[j][i];
    }
  }
  vector<unsigned char> key1(16);
  
  //recover each byte of the key individually
  #pragma omp parallel for
  for(int n = 0; n < 16; n++) {
    vector<vector<int>> simulatedTraces(256, vector<int>(sampleCountPhase2));
    for(int i = 0; i < sampleCountPhase2; i++) {
      mpz_class msg = messagesPhase2[i] >> (8 * n);
      //get the byte from the message which corresponds to the key byte we are recovering
      int byte = msg.get_si() & 0xff;
      for(int k = 0; k < 256; k++) {
        simulatedTraces[k][i] = HammingWeight[InvSubBytes[byte] ^ k];
      }
    }

    //calculate correlation between trace samples and our model
    vector<vector<double>>correlation(256, vector<double> (traceSize));
    for(int i = 0; i < 256; i++) {
      for(int j = 0; j < traceSize; j++) {
        correlation[i][j] = PearsonCorr(simulatedTraces[i], powerMatrix[j]);
      }
    }

    double maxCorr = -2;
    int bestByte = -1;
    for(int i = 0; i < 256; i++) {
      for(int j = 0; j < traceSize; j++) {
        if(correlation[i][j] > maxCorr) {
          maxCorr = correlation[i][j];
          bestByte = i;
        }
      }
    }
    key1[15 - n] = bestByte;
  }
  printf("Value of Key 1 is:");
  for(int n = 0; n < 16; n++){
    printf("%02X", (int)key1[n]);
  }
  printf("\n");
  return key1;
}

bool Attack::TestKey(vector<unsigned char> key1, vector<unsigned char> key2) {
  mpz_class sector(167771111002177);
  mpz_class message;
  mpz_class tweakedMessage;
  vector<int> currentTrace;
  vector<int> currentTracePhase2;
  Interact(0, sector, message, currentTrace, currentTracePhase2);

  unsigned char m_char[16] = {0}, t[16] = {0};
  unsigned char rev_m_char[16] = {0};
  mpz_export(m_char, NULL, 1, 1, 0, 0, sector.get_mpz_t());
  for(int i = 0 ; i <16; i++){
    rev_m_char[15 - i] = m_char[i];
  }

  printf("\n");
  AES_KEY rk;
  AES_set_encrypt_key(key2.data(), 128, &rk);
  AES_encrypt(rev_m_char, t, &rk);
     
  unsigned char res[16] = {0};
  AES_KEY sk;
  AES_set_encrypt_key(key1.data(), 128, &sk);
  AES_decrypt(t, res, &sk);

  mpz_class PP, T;
  mpz_import(PP.get_mpz_t(), 16, 1, 1, 1, 0, res);
  mpz_import(T.get_mpz_t(), 16, 1, 1, 1, 0, t);    
  mpz_class P = PP ^ T;
  if( P == message){
    return true;
  } else {
    gmp_printf("%ZX\n%ZX\n\n",P,message);
    return false;
  }
}

void Attack::throwErrorAndAbort(string errorMessage) {
  cerr<<errorMessage<<endl;
  cleanup(-1);
}
#endif