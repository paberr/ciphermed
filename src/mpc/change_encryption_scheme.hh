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

#include <gmpxx.h>

#include <crypto/gm.hh>

#include <FHE.h>
#include <crypto/paillier.hh>
#include <EncryptedArray.h>

#include <vector>

using namespace std;

class Change_ES_FHE_from_GM_A {
public:
//    Change_ES_FHE_from_GM_A()

    mpz_class blind(const mpz_class &c, GM &gm, gmp_randstate_t state);
    Ctxt unblind(const Ctxt &c, const FHEPubKey& publicKey, const EncryptedArray &ea);
protected:
    bool coin_;
};

class Change_ES_FHE_from_GM_B {
    public:
    static Ctxt decrypt_encrypt(const mpz_class &c, GM_priv &gm, const FHEPubKey &publicKey, const EncryptedArray &ea);
};


/*
 * Weird naming: Changes GM to FHE...
 */
class Change_ES_FHE_from_GM_slots_A {
    public:
    //    Change_ES_FHE_from_GM_A()
    
    vector<mpz_class> blind(const vector<mpz_class> &c, GM &gm, gmp_randstate_t state, unsigned long n_slots);
    Ctxt unblind(const Ctxt &c, const FHEPubKey& publicKey, const EncryptedArray &ea);
    protected:
    vector<long> coins_;
};

class Change_ES_FHE_from_GM_slots_B {
    public:
    static Ctxt decrypt_encrypt(const vector<mpz_class> &c, GM_priv &gm, const FHEPubKey &publicKey, const EncryptedArray &ea);
};

/*
 * Changes FHE to GM
 */
class Change_GM_from_ES_FHE_slots_A {
public:

    vector<mpz_class> unblind(const vector<mpz_class> &c, GM &gm);
    Ctxt blind(const Ctxt &c, const FHEPubKey& publicKey, const EncryptedArray &ea, gmp_randstate_t state, unsigned long n_slots);
protected:
    vector<long> coins_;
};

class Change_GM_from_ES_FHE_slots_B {
public:
    static vector<mpz_class> decrypt_encrypt(const Ctxt &c, GM &gm, const FHESecKey &privateKey, const EncryptedArray &ea);
};

/*
 * Changes GM to Paillier
 */
class Change_Paillier_from_GM_slots_A {
public:

    vector<mpz_class> blind(const vector<mpz_class> &c_gm, GM &gm, gmp_randstate_t state, unsigned long n_slots);
    vector<mpz_class> unblind(const vector<mpz_class> &c_p, Paillier &publicKey);
protected:
    vector<bool> coins_;
};

class Change_Paillier_from_GM_slots_B {
public:
    static vector<mpz_class> decrypt_encrypt(const vector<mpz_class> &c_gm, GM_priv &gm, Paillier &publicKey);
};

/*
 * Changes FHE to Paillier
 */
class Change_Paillier_from_ES_FHE_slots_A {
public:

    Ctxt blind(const Ctxt &c, const FHEPubKey& publicKey, const EncryptedArray &ea, gmp_randstate_t state, unsigned long n_slots);
    vector<mpz_class> unblind(const vector<mpz_class> &c_p, Paillier &publicKey);
protected:
    vector<long> coins_;
};

class Change_Paillier_from_ES_FHE_slots_B {
public:
    static vector<mpz_class> decrypt_encrypt(const Ctxt &c, Paillier &publicKey, const FHESecKey &privateKey, const EncryptedArray &ea);
};

/*
 * Changes Paillier (encrypted by client, known by server) to Paillier (encrypted by server, known by client)
 */
class Move_Paillier_A {
public:

    vector<mpz_class> blind(const vector<mpz_class> &c_p, Paillier &publicKey, gmp_randstate_t state);
    vector<mpz_class> enc_noise(Paillier &ownKey);

protected:
    vector<mpz_class> noise_;
};

class Move_Paillier_B {
public:
    vector<mpz_class> unblind(const vector<mpz_class> &c_p, const vector<mpz_class> &noise, const Paillier &publicKey);
    static vector<mpz_class> decrypt_encrypt(const vector<mpz_class> &c_p, Paillier_priv &privateKey, Paillier &otherKey);
};