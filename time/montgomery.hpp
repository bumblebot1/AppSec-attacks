#ifndef __MONTGOMERY_HPP
#define __MONTGOMERY_HPP

#include <gmpxx.h>
/*
 * Struct to define the functions for montgomery multiplication.
 * This approach makes it similar to a class in an object oriented language.
 */
class Montgomery {
  public:
    void Multiplication(mpz_t res, mpz_t x, mpz_t y, mp_limb_t omega, mpz_t N);
    mp_limb_t GetOmega(mpz_t N);
    void GetRhoSquared(mpz_t rhoSquared, mpz_t N);
    void Convert(mpz_t res, mpz_t num, mpz_t rho_sq, mp_limb_t omega, mpz_t N);
    void Reduce(mpz_t res, mpz_t t, mp_limb_t omega, mpz_t N);
};
/**
  * Montgomery multiplication function
  * it sets res <- x * y * (rho ^-1) (mod N)
  */
void Montgomery::Multiplication(mpz_t res, mpz_t x, mpz_t y, mp_limb_t omega, mpz_t N) {
  mpz_t r;
  mpz_init(r);
  
  mpz_set_ui(r, 0);
  mp_limb_t u, y_i, x_0, r_0;
  
  for (mp_size_t i = 0; i < mpz_size(N); i++) {
    y_i = mpz_getlimbn(y, i); // i-th limb of y
    x_0 = mpz_getlimbn(x, 0); // 0-th limb of x
    r_0 = mpz_getlimbn(r, 0); // 0-th limb of r
    u = (r_0 + y_i * x_0) * omega;
    
    mpz_addmul_ui(r, x, y_i); 
    mpz_addmul_ui(r, N, u);   
    mpz_tdiv_q_2exp(r, r, mp_bits_per_limb);
  }
  
  mpz_swap(res, r);
}

/**
  * Function to calculate omega, parameter to be used in the other montgomery form operations.
  * omega = N ^ -1 (mod b)
  * In my implementation b = mp_bits_per_limb 
  */
mp_limb_t Montgomery::GetOmega(mpz_t N) {
  mp_limb_t omega = 1;
  
  mp_limb_t N0 = mpz_getlimbn(N, 0);
  
  for (mp_size_t i = 1; i <= mp_bits_per_limb; i++) {
    // since base is equal to 2^mp_bits_per_limb N mod b = 0th limb of N
    omega *= omega * N0;
    // due to the base size we do not need to perform any mod operations 
    // since overflow will automatically take care of these
  }
  
  // we return -omega since we want to find the inverse of omega
  // again due to overflow simply negating the number will return the desired result 
  return -omega;
}

/**
  * Function to calculate rho ^ 2, parameter to be used in the other montgomery form operations.
  * rhoSquared <- rho ^ 2 (mod N)
  */
void Montgomery::GetRhoSquared(mpz_t rhoSquared, mpz_t N) {
  mpz_set_ui(rhoSquared, 1);
  
  // upto 2 * l_N * w
  for (mp_size_t i = 0; i < 2 * mpz_size(N) * mp_bits_per_limb; i++) {
    // rho^2 <- rho^2 + rho^2
    mpz_add(rhoSquared, rhoSquared, rhoSquared);
    
    if (mpz_cmp(rhoSquared, N) >= 0) {
      mpz_sub(rhoSquared, rhoSquared, N);
    }
  }
}

/**
  * Montgomery conversion function.
  * This function converts a given number num into montgomery form.
  * res <- num * rho (mod N)
  */
void Montgomery::Convert(mpz_t res, mpz_t num, mpz_t rho_sq, mp_limb_t omega, mpz_t N) {
  Multiplication(res, num, rho_sq, omega, N);
}


/**
  * Montgomery reduction function
  * res <- t * (rho ^ -1)
  */
void Montgomery::Reduce(mpz_t res, mpz_t t, mp_limb_t omega, mpz_t N) {
  mpz_t r;
  mpz_init(r);
  
  mpz_set(r, t);
  
  mpz_t temp;
  mpz_init(temp);
  mp_limb_t u, r_i;
  
  for (mp_size_t i = 0; i < mpz_size(N); i++) {
    r_i = mpz_getlimbn(r,i);

    u = r_i * omega;
    
    mpz_mul_2exp(temp, N, mp_bits_per_limb * i);
    mpz_addmul_ui(r, temp, u);
  }

  mpz_tdiv_q_2exp(r, r, mp_bits_per_limb * mpz_size(N) );
  
  if(mpz_cmp(r,N) >= 0) {
    mpz_sub(r,r,N);
  }
  mpz_swap(res, r);
}

#endif