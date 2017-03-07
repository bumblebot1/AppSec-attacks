#ifndef __ATTACK_HPP
#define __ATTACK_HPP

#include  <iostream>
#include  <cstring>
#include  <gmpxx.h>
#include  <fstream>

using namespace std;

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
  
  public:
    Attack(ifstream& input, FILE* in, FILE* out);
    int Oracle(mpz_class challenge);
    mpz_class Stage1();
    mpz_class Stage2(mpz_class f1);
    mpz_class Stage3(mpz_class f2);
    void printAll();
    void Execute();
};

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
  if(res == 1) {
    return code; //return the code if it was read otherwise error should be caught
  }

  return NORESULT;
}

mpz_class Attack::Stage1() {
  mpz_class f1(2);
  int code = Oracle(f1);

  while(code == ERROR2) {
    f1 = f1 * 2;
    code = Oracle(f1);
  }

  return f1;
}

mpz_class Attack::Stage2(mpz_class f1) {
  mpz_class f1over2 = f1 / 2;

  mpz_class f2;
  f2 = ((N + B) / B) * f1over2;
  int code = Oracle(f2);

  while(code == ERROR1) {
    f2 = f2 + f1over2;
    code = Oracle(f2);
  }

  return f2;
}

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
      // "throw exception here"
    }
  }
  return m_min;
}

void Attack::Execute() {
  mpz_class f1 = Stage1();
  mpz_class f2 = Stage2(f1);
  mpz_class f3 = Stage3(f2);
  gmp_printf("%ZX\n", f1);
  gmp_printf("%ZX\n", f2);
  gmp_printf("%0*ZX\n", mpz_sizeinbase(N.get_mpz_t(), 16), f3);
}

void Attack::printAll() {
  gmp_printf("%ZX\n\n%ZX\n\n%ZX\n\n%ZX\n\n", N, e, label, c);
}

#endif