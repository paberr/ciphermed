/*
 * Copyright 2013-2015 Raphael Bost
 * Copyright 2016-2017 Pascal Berrang
 *
 * This file is part of ciphermed-forests.

 *  ciphermed-forests is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 * 
 *  ciphermed-forests is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with ciphermed-forests.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <list>
#include <vector>
#include <NTL/ZZ.h>
#include <math/mpz_class.hh>

class Paillier {
 public:
    Paillier(const std::vector<mpz_class> &pk, gmp_randstate_t state);
    std::vector<mpz_class> pubkey() const { return { n, g }; }

    mpz_class encrypt(const mpz_class &plaintext);
    mpz_class add(const mpz_class &c0, const mpz_class &c1) const;
    mpz_class sub(const mpz_class &c0, const mpz_class &c1) const;
    mpz_class constMult(const mpz_class &m, const mpz_class &c) const;
    mpz_class constMult(long m, const mpz_class &c) const;
    mpz_class constMult(const mpz_class &c, long m) const { return constMult(m,c); };
    mpz_class scalarize(const mpz_class &c);
    mpz_class constXor(bool b, const mpz_class &c) const;
    mpz_class constXor(const mpz_class &c, bool b) const { return constXor(b,c); };
    void refresh(mpz_class &c);
    mpz_class random_encryption();

    mpz_class dot_product(const std::vector<mpz_class> &c, const std::vector<mpz_class> &v);
    mpz_class dot_product(const std::vector<mpz_class> &c, const std::vector<long> &v);
    void rand_gen(size_t niter = 100, size_t nmax = 1000);

 protected:
    /* Public key */
    const mpz_class n, g;

    /* Randomness state */
    gmp_randstate_t _randstate;

    /* Cached values */
    const uint nbits;
    const mpz_class n2;
    bool good_generator;
    
    /* Pre-computed randomness */
    std::list<mpz_class> rqueue;
};

class Paillier_priv : public Paillier {
 public:
    Paillier_priv(const std::vector<mpz_class> &sk, gmp_randstate_t state);
    std::vector<mpz_class> privkey() const { return { p, q, g, a }; }
    void find_crt_factors();
    
    // if a !=0, and if you are encrypting using the private key, use this function
    // 75% speedup
    mpz_class encrypt(const mpz_class &plaintext);
    // no speedup compared to the fast_encrypt
    mpz_class fast_encrypt_precompute(const mpz_class &plaintext);

    mpz_class decrypt(const mpz_class &ciphertext) const;
    static std::vector<mpz_class> keygen(gmp_randstate_t state, uint nbits = 1024, uint abits = 256);


 protected:
    /* Private key, including g from public part; n=pq */
    const mpz_class p, q;
    const mpz_class a;      /* non-zero for fast mode */

    /* Cached values */
    const bool fast;
    const mpz_class p2, q2;
    mpz_class e_p2, e_q2;
    const mpz_class two_p, two_q;
    const mpz_class pinv, qinv;
    const mpz_class hp, hq;
};

class Paillier_priv_fast : public Paillier_priv {
public:
    Paillier_priv_fast(const std::vector<mpz_class> &sk, gmp_randstate_t state);
    void precompute_powers();
    mpz_class compute_g_star_power(const mpz_class &x);
    static std::vector<mpz_class> keygen(gmp_randstate_t state, uint nbits = 1024);
    
    mpz_class encrypt(const mpz_class &plaintext);
private:
    const mpz_class g_star_;
    const mpz_class phi_n;
    const mpz_class phi_n2;
    const uint phi_n2_bits;
    std::vector<mpz_class> g_star_powers_p_;
    std::vector<mpz_class> g_star_powers_q_;
};
