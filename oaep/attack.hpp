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
    mpz_class N, e, label, c, B;
    FILE* target_in;
    FILE* target_out;
    unsigned long interactionCount;
  
  private:
    int Oracle(mpz_class challenge);
    mpz_class Stage1();
    mpz_class Stage2(mpz_class f1);
    mpz_class Stage3(mpz_class f2);
    vector<unsigned char>  EME_OAEP_Decode(mpz_class attackResult);
    void throwErrorAndAbort(string errorMessage);
  
  public:
    Attack(ifstream& input, FILE* in, FILE* out);
    void Execute();
};

/**
 * @brief Constructor for the Attack Class.
 *
 * @param input  ifstream of the conf file.
 * @param in     pointer to the stdin of the target.
 * @param out    pointer to the stdout of the target.
 */
Attack::Attack(ifstream& input, FILE* in, FILE* out) {
  string line;
  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", N);
  
  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", e);
  
  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", label);
  
  getline(input, line);
  gmp_sscanf(line.c_str(), "%ZX", c);
  interactionCount = 0;

  size_t k = mpz_sizeinbase(N.get_mpz_t(), 256);
  mpz_powm_ui(B.get_mpz_t(), mpz_class(2).get_mpz_t(), 8 * (k - 1), N.get_mpz_t());

  target_in  = in;
  target_out = out;
}

/**
 * @brief Function to interact with the attack target
 *        corresponding to the oracle queries in Manger's paper.
 *
 * @param f is an mpz_class object used to calculate (f^e) * c (mod N) which is the query to the oracle.
 */
int Attack::Oracle(mpz_class f) {
  mpz_class challenge(0);

  mpz_powm(challenge.get_mpz_t(), f.get_mpz_t(), e.get_mpz_t(), N.get_mpz_t());
  challenge = (challenge * c) % N;
  gmp_fprintf(target_in, "%ZX\n", label);
  gmp_fprintf(target_in, "%0*ZX\n", mpz_sizeinbase(N.get_mpz_t(), 16), challenge);
  fflush(target_in);

  //get back error code
  int code;
  int res = fscanf(target_out, "%X", &code);
  interactionCount++;
  
  if(res == 1) {
    return code; //return the code if it was read otherwise error should be caught
  }
  
  throwErrorAndAbort("No error code returned from the Oracle!");  
}

/**
 * @brief Function corresponding to Step1 of the attack described in the paper.
 *
 * f1 <- 2
 * while query_oracle(f1) returns "<B"
 *    f1 <- f1 * 2
 *
 * @return f1
 */
mpz_class Attack::Stage1() {
  mpz_class f1(2);
  int code = Oracle(f1);

  while(code == ERROR2) {
    f1 = f1 * 2;
    code = Oracle(f1);
  }

  if(code != ERROR1) {
    throwErrorAndAbort("Malformed interaction during stage 1. Error code is: " + to_string(code));
  }

  return f1;
}

/**
 * @brief Function corresponding to Step2 of the attack described in the paper.
 *
 * @param f1  the value returned from Step1.
 *
 * f2 <- floor((N + B) / B) * (f1 / 2)
 * while query_oracle(f2) returns ">=B"
 *    f2 <- f2 + f1 / 2
 *
 * @return f2
 */
mpz_class Attack::Stage2(mpz_class f1) {
  mpz_class f1over2 = f1 / 2;

  mpz_class f2;
  f2 = ((N + B) / B) * f1over2;
  int code = Oracle(f2);

  while(code == ERROR1) {
    f2 = f2 + f1over2;
    code = Oracle(f2);
  }

  if(code != ERROR2) {
    throwErrorAndAbort("Malformed interaction during stage 2. Error code is: " + to_string(code));
  }

  return f2;
}

/**
 * @brief Function corresponding to Step3 of the attack described in the paper.
 *
 * @param f2  the value returned from Step2.
 *
 * m_min <- ceil(N / f2)
 * m_max <- floor((N + B) / f2)
 * while m_min < m_max
 *    ftmp <- floor(2 * B / (m_max - m_min))
 *    i    <- floor(ftmp * m_min / N)
 *    f3   <- ceil(i * N / m_min)
 *    query_oracle(f3)
 *    if ">=B" :
 *      m_min <- ceil((i * N + B) / f3)
 *    else if "< B" :
 *      m_max <- floor((i * N + B) / f3)
 *
 * @return m_min (the actual value of the message that has been recovered)
 */
mpz_class Attack::Stage3(mpz_class f2) {
  mpz_class m_min, m_max;
  mpz_cdiv_q(m_min.get_mpz_t(), N.get_mpz_t(), f2.get_mpz_t());
  m_max = (N + B) / f2;

  while(mpz_cmp(m_min.get_mpz_t(), m_max.get_mpz_t()) != 0) {
    mpz_class ftmp = 2 * B / (m_max - m_min);
    mpz_class i = (ftmp * m_min) / N;
    mpz_class i_N = i * N;
    mpz_class f3;
    mpz_cdiv_q(f3.get_mpz_t(), i_N.get_mpz_t(), m_min.get_mpz_t());
    int code = Oracle(f3);
    
    i_N = i_N + B;
    if(code == ERROR1) {
      mpz_cdiv_q(m_min.get_mpz_t(), i_N.get_mpz_t(), f3.get_mpz_t());
    } else if(code == ERROR2) {
      m_max = i_N / f3;
    } else {
      throwErrorAndAbort("Bad error code returned in Stage3; The code is:" + to_string(code));
    }
  }
  return m_min;
}

/**
 * @brief Function which performs the OAEP decoding stage and recovers the actual plaintext.
 *
 * @param attackResult  the value obtained after running Step3.
 *
 * @return message  vector<unsigned char> the actual plaintext converted to octet string.
 */
vector<unsigned char> Attack::EME_OAEP_Decode(mpz_class attackResult) {
  //convert attackResult into octet string
  size_t len = mpz_sizeinbase(attackResult.get_mpz_t(), 256);
  unsigned char buffer[len + 1] = {0};
  mpz_export(buffer + 1, NULL, 1, 1, 0, 0, attackResult.get_mpz_t());

   //convert label into octet string
  len = mpz_sizeinbase(label.get_mpz_t(), 256);
  unsigned char bufferLabel[len] = {0};
  mpz_export(bufferLabel, NULL, 1, 1, 0, 0, label.get_mpz_t());

  unsigned char hashedLabel[SHA_DIGEST_LENGTH];
  // hash the label
  SHA1(bufferLabel, len, hashedLabel);

  size_t k = mpz_sizeinbase(N.get_mpz_t(), 256);
  int i = 0;
  unsigned char maskedSeed[SHA_DIGEST_LENGTH];
  for(i = 0; i < SHA_DIGEST_LENGTH; i++) {
    maskedSeed[i] = buffer[i + 1];
  }

  unsigned char maskedDB[k - SHA_DIGEST_LENGTH - 1];
  for(i = 0; i < k - SHA_DIGEST_LENGTH - 1; i++) {
    maskedDB[i] = buffer[i + SHA_DIGEST_LENGTH + 1];
  }  

  unsigned char seedMask[SHA_DIGEST_LENGTH];
  PKCS1_MGF1(seedMask, SHA_DIGEST_LENGTH, maskedDB, k - SHA_DIGEST_LENGTH - 1, EVP_sha1());

  unsigned char seed[SHA_DIGEST_LENGTH];
  for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
    seed[i] = maskedSeed[i] ^ seedMask[i];  
  }

  unsigned char dbMask[k - SHA_DIGEST_LENGTH - 1];
  PKCS1_MGF1(dbMask, k - SHA_DIGEST_LENGTH - 1,  seed, SHA_DIGEST_LENGTH, EVP_sha1());

  vector<unsigned char> DB(k - SHA_DIGEST_LENGTH -1);
  for (i = 0; i < k - SHA_DIGEST_LENGTH - 1; i++) {
    DB[i] = maskedDB[i] ^ dbMask[i];  
  }

  unsigned char hashPrime[SHA_DIGEST_LENGTH];
  for(i = 0; i < SHA_DIGEST_LENGTH; i++){
    hashPrime[i] = DB[i];
  }

  for(i = SHA_DIGEST_LENGTH; i < k - SHA_DIGEST_LENGTH - 1; i++) {
    if(DB[i] != 0)
      break;
  }

  if(i == SHA_DIGEST_LENGTH){
    //output error since there is no 01 octet
    throwErrorAndAbort("Malformed Data Block(DB) in EME_OAEP_Decode");
  }

  vector<unsigned char> message(DB.begin() + i + 1, DB.end());

  for(int index = 0; index < SHA_DIGEST_LENGTH; index++) {
    if(hashedLabel[index] != hashPrime[index]) {
      cerr<<"Error during hash verification"<<endl;
    }
  }
  cerr<<"Hash was verified correctly"<<endl;

  return message;
}

/**
 * @brief Driver function which performs all the steps of the attack and prints any relevant output to stdout or sterr.
 */
void Attack::Execute() {
  mpz_class f1 = Stage1();
  mpz_class f2 = Stage2(f1);
  mpz_class f3 = Stage3(f2);
  gmp_printf("The OAEP message is:\n%0*ZX\n\n", mpz_sizeinbase(N.get_mpz_t(), 16), f3);
  
  vector<unsigned char> message = EME_OAEP_Decode(f3);
  cout<<"Recovered message is:"<<endl;
  for(unsigned char byte : message) {
    printf("%02X", (unsigned int)byte);
  }
  cout<<"\n\n";
  cout<<"There were "<<interactionCount<<" interactions with the target."<<endl<<endl;
}

/**
 * @brief Function which aborts execution and prints an error message to stderr.
 *
 * @param errorMessage  the error message to be printed to stderr
 */
void Attack::throwErrorAndAbort(string errorMessage) {
  cerr<<errorMessage<<endl;
  abort();
}

#endif