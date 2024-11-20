#include "test_prime.cpp"


extern "C"{
    void rust_genprime(mpz_ptr p, unsigned int p_bits, unsigned int p_min_bits, unsigned int k, unsigned int tmp_seed){
        generate_prime_optimized(p, p_bits, p_min_bits, k, tmp_seed);
    }
    void rust_genprime_safe(mpz_ptr p, unsigned int p_bits, unsigned int k, unsigned int tmp_seed){
    	generate_prime_safe(p, p_bits, k, tmp_seed);
    }
}
