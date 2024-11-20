#define BHJL_HE_MR_INTERATIONS 16

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
//#include <iostream>
#include <chrono>
#include <thread>
using namespace std;

void generate_pi_and_phi_pi(mpz_ptr pi, mpz_ptr phi, mpz_srcptr r_min, mpz_srcptr r_max, unsigned int ratio){
    unsigned int primes_len = 434;
    unsigned int primes[] = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037};

    mpz_t rmax_rmin,min_pi,TWO;
    mpz_init (rmax_rmin);
    mpz_init (min_pi);
    mpz_init (TWO);

    mpz_set_ui (TWO, 2);

    mpz_sub(rmax_rmin, r_max, r_min);
    //gmp_printf ("rmax - rmin: %Zd\n", rmax_rmin);
    size_t len_rmax_rmin = mpz_sizeinbase(rmax_rmin, 2);
    //cout << "(rmax - rmin) bits length: "<< len_rmax_rmin << endl;

    mpz_pow_ui (min_pi, TWO, len_rmax_rmin - ratio);

    //cout << "rmax-rmin: "<< t << endl;
    for(int i = 0; i < primes_len; i++){
        if(mpz_cmp (pi, min_pi) > 0){
            break;
        }

        mpz_mul_ui (pi, pi, primes[i]);
        mpz_lcm_ui (phi, phi, primes[i] - 1);
    }

    mpz_clear (rmax_rmin);
    mpz_clear (min_pi);
    mpz_clear (TWO);
}

void generate_prime_optimized (mpz_ptr p, unsigned long int p_bits, unsigned long int p_min_bits, unsigned long int k, unsigned long int tmp_seed){
    //cout << "Optimized generation starts." << endl;
    mpz_t pi,phi,r_max,r_min,two_pow_k,ZERO,ONE,TWO,seed;

    gmp_randstate_t prng;
    gmp_randinit_mt(prng);

    mpz_init (pi);
    mpz_init (phi);
    mpz_init (r_max);
    mpz_init (r_min);
    mpz_init (two_pow_k);
    mpz_init (ZERO);
    mpz_init (ONE);
    mpz_init (TWO);
    mpz_init (seed);

    mpz_set_ui (pi, 1);
    mpz_set_ui (phi, 1);
    mpz_set_ui (ZERO, 0);
    mpz_set_ui (ONE, 1);
    mpz_set_ui (TWO, 2);
    mpz_pow_ui (two_pow_k, TWO, k);
    mpz_set_ui(seed, tmp_seed);

    gmp_randseed(prng, seed);

    mpz_pow_ui (r_max, TWO, p_bits);
    mpz_sub (r_max, r_max, ONE);
    mpz_fdiv_q (r_max, r_max, two_pow_k);

    mpz_pow_ui (r_min, TWO, p_min_bits);
    mpz_sub (r_min, r_min, ONE);
    mpz_fdiv_q (r_min, r_min, two_pow_k);

    generate_pi_and_phi_pi(pi, phi, r_min, r_max, 10);

    //gmp_printf ("pi: %Zd\n", pi);
    //cout << "pi bits length: "<< mpz_sizeinbase(pi, 2) << endl;
    //gmp_printf ("phi: %Zd\n", phi);
    //cout << "phi bits length: "<< mpz_sizeinbase(phi, 2) << endl;

    mpz_t v,v1,one_minus_v_phi,u,r;
    mpz_init (v);
    mpz_init (v1);
    mpz_init (one_minus_v_phi);
    mpz_init (u);
    mpz_init (r);

    // random v, u = (1 - v^{phi}) mod pi
    mpz_urandomm (v, prng, pi);
    mpz_powm (one_minus_v_phi, v, phi, pi); //v^{phi}
    mpz_sub (one_minus_v_phi, ONE, one_minus_v_phi); //1 - v^{phi}
    mpz_mod (u, one_minus_v_phi, pi); //(1 - v^{phi}) mod pi

    while(mpz_cmp (u, ZERO) != 0){
        mpz_urandomm (r, prng, pi);
        mpz_mul (v1, r, u); //v1 = r*u
        mpz_mod (v1, v1, pi); //v1 = r*u mod pi
        mpz_add (v, v, v1); // v = v + v1
        mpz_powm (one_minus_v_phi, v, phi, pi); //v^{phi}
        mpz_sub (one_minus_v_phi, ONE, one_minus_v_phi); //1 - v^{phi}
        mpz_mod (u, one_minus_v_phi, pi); //(1 - v^{phi}) mod pi
    }
    //gmp_printf ("u: %Zd\n", u);

    mpz_t two_k_inv,sum,v0,t;
    mpz_init (two_k_inv);
    mpz_init (sum);
    mpz_init (v0);
    mpz_init (t);

    mpz_invert (two_k_inv, two_pow_k, pi);
    mpz_add (sum, two_k_inv, r_min); // 1/2^k + r_min
    mpz_sub (v0, ZERO, sum); // 0 - (1/2^k + r_min)
    mpz_mod (v0, v0, pi); // - (1/2^k + r_min) mod pi
    mpz_mod (t, v, pi); // v mod pi
    mpz_add (t, t, v0); // - (1/2^k + r_min) mod pi + v mod pi

    mpz_add (p, r_min, t);
    mpz_mul (p, p, two_pow_k);
    mpz_add (p, ONE, p);

    while(!mpz_probab_prime_p(p, BHJL_HE_MR_INTERATIONS)){
        mpz_mul (v, TWO, v);
        mpz_mod (v, v, pi);
        mpz_mod (t, v, pi); // v mod pi
        mpz_add (t, t, v0); // - (1/2^k + r_min) mod pi + v mod pi
        mpz_add (p, r_min, t); // r_min + t
        mpz_mul (p, p, two_pow_k); // (r_min + t) * 2^k
        mpz_add (p, ONE, p); //1 + (r_min + t) * 2^k
    }
    
    if (mpz_probab_prime_p(p, BHJL_HE_MR_INTERATIONS)){
        //cout << "p is prime "<< endl;
    }

    mpz_clear (two_k_inv);
    mpz_clear (sum);
    mpz_clear (v0);
    mpz_clear (t);
    mpz_clear (v);
    mpz_clear (v1);
    mpz_clear (one_minus_v_phi);
    mpz_clear (u);
    mpz_clear (r);
    mpz_clear (pi);
    mpz_clear (phi);
    mpz_clear (r_max);
    mpz_clear (r_min);
    mpz_clear (two_pow_k);
    mpz_clear (ONE);
    mpz_clear (seed);
    gmp_randclear (prng);
}

void generate_prime_safe (mpz_ptr p, unsigned long int p_bits, unsigned long int  plaintext_bits, unsigned long int tmp_seed){
    //cout << "Exhausted generation starts." << endl;
    mpz_t tmp, seed;

    gmp_randstate_t prng;
    gmp_randinit_mt(prng);


    mpz_inits(seed, tmp, NULL);

    mpz_set_ui(seed, tmp_seed);

    gmp_randseed(prng, seed);

    mpz_set_ui(p, 0);

    if (mpz_cmp_ui(p, 0) == 0) { /* to support precomputed safe primes */
        do {
            do {
                mpz_urandomb(tmp, prng, p_bits - plaintext_bits);
                mpz_setbit(tmp, p_bits - plaintext_bits - 1);
                mpz_setbit(tmp, 0);
            } while (!mpz_probab_prime_p(tmp, BHJL_HE_MR_INTERATIONS));
            mpz_mul_2exp(p, tmp, plaintext_bits);
            mpz_setbit(p, 0);
        } while (!mpz_probab_prime_p(p, BHJL_HE_MR_INTERATIONS));
    }

    if (mpz_probab_prime_p(p, BHJL_HE_MR_INTERATIONS)){
        //cout << "p is prime "<< endl;
    }

    mpz_clear (seed);
    mpz_clear (tmp);
    gmp_randclear (prng);

}

/*
int main()
{
    
    unsigned int p_bits, p_min_bits, k;

    mpz_t p,p1;
    mpz_init (p);
    mpz_init (p1);
    

    p_bits = 3840;
    p_min_bits = 3839;
    k = 1168;
    //cout << "p_bits: "<< p_bits << endl;
    //cout << "p_min_bits: "<< p_min_bits << endl;
    //cout << "k: "<< k << endl;

    auto start_time = chrono::steady_clock::now();
    generate_prime_optimized(p, p_bits, p_min_bits, k, 3623);
    gmp_printf ("p: %Zd\n", p);
    auto end_time = chrono::steady_clock::now(); // end to count the time

    auto running_time = end_time - start_time;
    cout << "Optimized generation takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    cout << "----------------------------------------------------- "<< endl;

    start_time = chrono::steady_clock::now();
    generate_prime_general (p1, p_bits, k, 52);
    gmp_printf ("p: %Zd\n", p1);
    end_time = chrono::steady_clock::now(); // end to count the time

    running_time = end_time - start_time;
    cout << "Exhausted generation takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    mpz_clear (p);
    mpz_clear (p1);
    return 0;
}
*/

