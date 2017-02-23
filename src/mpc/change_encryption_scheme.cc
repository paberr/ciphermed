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

#include <mpc/change_encryption_scheme.hh>
#include <NTL/ZZX.h>
#include <iostream>

#define BLINDING 1

#include <algorithm>

using namespace NTL;
using namespace std;

mpz_class Change_ES_FHE_from_GM_A::blind(const mpz_class &c, GM &gm, gmp_randstate_t state)
{
#ifndef BLINDING
    coin_ = 0;
    return c;
#endif
    coin_ = gmp_urandomb_ui(state,1);
    
    if (coin_) {
        return gm.neg(c);
    }

    return c;
}

Ctxt Change_ES_FHE_from_GM_A::unblind(const Ctxt &c, const FHEPubKey& publicKey, const EncryptedArray &ea)
{
    if (coin_) {
        Ctxt d(c);
        
        NewPlaintextArray array(ea);
        encode(ea, array, 1);
        ZZX poly;
        ea.encode(poly,array);
        
        d.addConstant(poly);
        
        return d;
    }
    
    return c;
}


Ctxt Change_ES_FHE_from_GM_B::decrypt_encrypt(const mpz_class &c, GM_priv &gm, const FHEPubKey &publicKey, const EncryptedArray &ea)
{
    bool b = gm.decrypt(c);

#ifndef BLINDING
    cout << "Got bit " << b << endl;
#endif

    NewPlaintextArray array(ea);
    encode(ea, array, b);
    
    Ctxt c0(publicKey);
    ea.encrypt(c0, publicKey, array);

    return c0;
}



vector<mpz_class> Change_ES_FHE_from_GM_slots_A::blind(const vector<mpz_class> &c, GM &gm, gmp_randstate_t state, unsigned long n_slots)
{
    size_t n = std::min<size_t>(c.size(),n_slots);
    vector<mpz_class> rand_c(n_slots);

#ifndef BLINDING
    coins_ = vector<long>(n, 0);
    for (size_t i = 0; i < n; i++) {
        rand_c[i] = c[i];
    }
    return rand_c;
#endif

    coins_ = vector<long>(n);
    
    for (size_t i = 0; i < n; i++) {
        coins_[i] = gmp_urandomb_ui(state,1);
        
        if (coins_[i]) {
            rand_c[i] = gm.neg(c[i]);
        }else{
            rand_c[i] = c[i];
        }
    }
    
    return rand_c;
}

Ctxt Change_ES_FHE_from_GM_slots_A::unblind(const Ctxt &c, const FHEPubKey& publicKey, const EncryptedArray &ea)
{
    Ctxt d(c);
    
    NewPlaintextArray array(ea);
    encode(ea, array, coins_);
    ZZX poly;
    ea.encode(poly,array);
    
    d.addConstant(poly);
    
    return d;
}

Ctxt Change_ES_FHE_from_GM_slots_B::decrypt_encrypt(const vector<mpz_class> &c, GM_priv &gm, const FHEPubKey &publicKey, const EncryptedArray &ea)
{
    vector<long> v(c.size());
    
    for (size_t i = 0; i < c.size(); i++) {
        v[i] = gm.decrypt(c[i]);
    }

#ifndef BLINDING
    cout << "Got bits ";
    for (size_t i = 0; i < c.size(); i++) {
        cout << v[i] << ", ";
    }
    cout << endl;
#endif
    
    NewPlaintextArray array(ea);
    encode(ea, array, v);
    
    Ctxt c0(publicKey);
    ea.encrypt(c0, publicKey, array);
    
    return c0;

}

vector<mpz_class> Change_GM_from_ES_FHE_slots_B::decrypt_encrypt(const Ctxt &c, GM &gm, const FHESecKey &privateKey,
                                                               const EncryptedArray &ea) {
    // decrypt and test
    vector<long> res_bits;
    ea.decrypt(c, privateKey, res_bits);

    vector<mpz_class> v(res_bits.size());

#ifndef BLINDING
    cout << "Got bits ";
    for (size_t i = 0; i < res_bits.size(); i++) {
        cout << res_bits[i] << ", ";
    }
    cout << endl;
#endif

    for (size_t i = 0; i < res_bits.size(); ++i) {
        bool b = (res_bits[i] != 0);
        v[i] = gm.encrypt(b);
    }

    return v;
}

vector<mpz_class> Change_GM_from_ES_FHE_slots_A::unblind(const vector<mpz_class> &c, GM &gm)
{
    size_t n = c.size();
    vector<mpz_class> real_c(n);

    for (size_t i = 0; i < n; i++) {
        if (coins_[i]) {
            real_c[i] = gm.neg(c[i]);
        }else{
            real_c[i] = c[i];
        }
    }

    return real_c;
}

Ctxt Change_GM_from_ES_FHE_slots_A::blind(const Ctxt &c, const FHEPubKey& publicKey, const EncryptedArray &ea, gmp_randstate_t state, unsigned long n_slots)
{
    Ctxt d(c);

#ifndef BLINDING
    coins_ = vector<long>(n_slots, 0);
    return d;
#endif

    // initialise coins
    coins_ = vector<long>(n_slots);

    for (size_t i = 0; i < n_slots; i++) {
        coins_[i] = gmp_urandomb_ui(state, 1);
    }

    NewPlaintextArray array(ea);
    encode(ea, array, coins_);
    ZZX poly;
    ea.encode(poly,array);

    d.addConstant(poly);

    return d;
}

vector<mpz_class> Change_Paillier_from_GM_slots_A::blind(const vector<mpz_class> &c, GM &gm, gmp_randstate_t state, unsigned long n_slots)
{
    size_t n = std::min<size_t>(c.size(),n_slots);
    vector<mpz_class> rand_c(n);
    coins_ = vector<bool>(n);

#ifndef BLINDING
    coins_ = vector<bool>(n, false);
    for (size_t i = 0; i < n; i++) {
        rand_c[i] = c[i];
    }
    return rand_c;
#endif

    for (size_t i = 0; i < n; ++i) {
        coins_[i] = gmp_urandomb_ui(state,1) != 0;

        if (coins_[i]) {
            rand_c[i] = gm.neg(c[i]);
        }else{
            rand_c[i] = c[i];
        }
    }

    return rand_c;
}

vector<mpz_class> Change_Paillier_from_GM_slots_A::unblind(const vector<mpz_class> &c_p, Paillier &publicKey)
{
    vector<mpz_class> c_p_unblinded(c_p.size());

    for (size_t i = 0; i < c_p.size(); ++i) {
        c_p_unblinded[i] = publicKey.constXor(coins_[i], c_p[i]);
        publicKey.refresh(c_p_unblinded[i]);
    }

    return c_p_unblinded;
}

vector<mpz_class> Change_Paillier_from_GM_slots_B::decrypt_encrypt(const vector<mpz_class> &c_gm, GM_priv &gm, Paillier &publicKey)
{
    vector<mpz_class> c_p(c_gm.size());

#ifndef BLINDING
    cout << "Got bits ";
#endif

    for (size_t i = 0; i < c_gm.size(); i++) {
        long v = gm.decrypt(c_gm[i]);
#ifndef BLINDING
        cout << v << ", ";
#endif
        c_p[i] = publicKey.encrypt(v);
    }

#ifndef BLINDING
    cout << endl;
#endif

    return c_p;

}

Ctxt Change_Paillier_from_ES_FHE_slots_A::blind(const Ctxt &c, const FHEPubKey &publicKey, const EncryptedArray &ea,
                                                gmp_randstate_t state, unsigned long n_slots) {
    Ctxt d(c);

#ifndef BLINDING
    coins_ = vector<long>(n_slots, 0);
    return d;
#endif

    // initialise coins
    coins_ = vector<long>(n_slots);

    for (size_t i = 0; i < n_slots; i++) {
        coins_[i] = gmp_urandomb_ui(state, 1);
    }

    NewPlaintextArray array(ea);
    encode(ea, array, coins_);
    ZZX poly;
    ea.encode(poly,array);

    d.addConstant(poly);

    return d;
}

vector<mpz_class>
Change_Paillier_from_ES_FHE_slots_A::unblind(const vector<mpz_class> &c_p, Paillier &publicKey) {
    vector<mpz_class> c_p_unblinded(c_p.size());

    for (size_t i = 0; i < c_p.size(); ++i) {
        bool b = coins_[i] != 0;
        c_p_unblinded[i] = publicKey.constXor(b, c_p[i]);
        publicKey.refresh(c_p_unblinded[i]);
    }

    return c_p_unblinded;
}

vector<mpz_class> Change_Paillier_from_ES_FHE_slots_B::decrypt_encrypt(const Ctxt &c, Paillier &publicKey,
                                                                       const FHESecKey &privateKey,
                                                                       const EncryptedArray &ea) {
    // decrypt and test
    vector<long> res_bits;
    ea.decrypt(c, privateKey, res_bits);

    vector<mpz_class> v(res_bits.size());

#ifndef BLINDING
    cout << "Got bits ";
#endif

    for (size_t i = 0; i < res_bits.size(); ++i) {
        bool b = (res_bits[i] != 0);
        v[i] = publicKey.encrypt(b);
#ifndef BLINDING
        cout << b << ", ";
#endif
    }
#ifndef BLINDING
    cout << endl;
#endif

    return v;
}

vector<mpz_class>
Move_Paillier_A::blind(const vector<mpz_class> &c_p, Paillier &publicKey, gmp_randstate_t state) {
    vector<mpz_class> randomized_values(c_p.size());
    noise_ = vector<mpz_class>(c_p.size());

    mpz_class n = (publicKey.pubkey())[0];
    for (size_t i = 0; i<c_p.size(); ++i) {
        mpz_class pt0;
        mpz_urandomm(pt0.get_mpz_t(),state,n.get_mpz_t());
        noise_[i] = pt0;
        randomized_values[i] = publicKey.add(c_p[i], publicKey.encrypt(noise_[i]));
    }
    return randomized_values;
}

vector<mpz_class> Move_Paillier_A::enc_noise(Paillier &ownKey) {
    vector<mpz_class> c_noise(noise_.size());
    for (size_t i = 0; i<noise_.size(); ++i) {
        c_noise[i] = ownKey.encrypt(noise_[i]);
    }
    return c_noise;
}

vector<mpz_class> Move_Paillier_B::unblind(const vector<mpz_class> &c_p, const vector<mpz_class> &noise, const Paillier &publicKey) {
    vector<mpz_class> unblinded_values(c_p.size());

    for (size_t i = 0; i<c_p.size(); ++i) {
        unblinded_values[i] = publicKey.sub(c_p[i], noise[i]);
    }
    return unblinded_values;
}

vector<mpz_class>
Move_Paillier_B::decrypt_encrypt(const vector<mpz_class> &c_p, Paillier_priv &privateKey, Paillier &otherKey) {
    vector<mpz_class> reencrypted_values(c_p.size());

    for (size_t i = 0; i<c_p.size(); ++i) {
        reencrypted_values[i] = otherKey.encrypt(privateKey.decrypt(c_p[i]));
    }
    return reencrypted_values;
}
