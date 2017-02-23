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

#include <vector>
#include <gmpxx.h>

#include <mpc/rev_enc_comparison.hh>

using namespace std;


Rev_EncCompare_Owner::Rev_EncCompare_Owner(const mpz_class &v_a, const mpz_class &v_b, const size_t &l, Paillier &p,Comparison_protocol_A* comparator, gmp_randstate_t state)
: a_(v_a), b_(v_b), bit_length_(l), paillier_(p), comparator_(comparator), is_set_up_(false), two_l_(0)
{
    assert(bit_length_ != 0);
    gmp_randinit_set(randstate_, state);
    mpz_setbit(two_l_.get_mpz_t(),bit_length_); // set two_l_ to 2^l
}

Rev_EncCompare_Owner::~Rev_EncCompare_Owner()
{
    if(comparator_ != NULL) {
        delete comparator_;
        comparator_ = NULL;
    }
}

void Rev_EncCompare_Owner::set_input(const mpz_class &v_a, const mpz_class &v_b)
{
    assert(!is_set_up_);
    a_ = v_a;
    b_ = v_b;
}

mpz_class Rev_EncCompare_Owner::setup(unsigned int lambda)
{
    mpz_class x, r, z, c;
    
    // x = b + 2^l - a
    x = paillier_.add(b_,paillier_.encrypt(two_l_));
    x = paillier_.sub(x,a_);
    
    mpz_urandomb(r.get_mpz_t(), randstate_, lambda+bit_length_);
    // z = x + r
    z = paillier_.add(x,paillier_.encrypt(r));

    // c = r mod 2^l
    c = r % two_l_;
    comparator_->set_value(c);
    
    bool r_l = (bool)mpz_tstbit(r.get_mpz_t(),bit_length_);
    c_r_l_ = comparator_->gm().encrypt(r_l);
    is_set_up_ = true;

    
//    cout << "l = " << bit_length_ << endl;
//    cout << "Owner setup: \nr = " << r << "\t" << r.get_str(2) << "\nr_l = " << r_l << "\nc = " << c << endl;
//    cout << "2^l = " << two_l_ << endl;
    return z;
}

mpz_class Rev_EncCompare_Owner::concludeProtocol(const mpz_class &c_z_l)
{
    mpz_class c_t_prime = comparator_->gm().neg(comparator_->output());
    
    // t = t' + z_l + r_l (over F_2)
    c_t_ = comparator_->gm().XOR(c_t_prime,c_r_l_);
    c_t_ = comparator_->gm().XOR(c_t_,c_z_l);
    
    return c_t_;
}

Rev_EncCompare_Helper::Rev_EncCompare_Helper(const size_t &l, Paillier_priv_fast &pp, Comparison_protocol_B *comparator)
: bit_length_(l), paillier_(pp), comparator_(comparator), is_set_up_(false),two_l_(0), is_protocol_done_(false)
{
    mpz_setbit(two_l_.get_mpz_t(),bit_length_); // set two_l_ to 2^l
}

Rev_EncCompare_Helper::~Rev_EncCompare_Helper()
{
    if(comparator_ != NULL) {
        delete comparator_;
        comparator_ = NULL;
    }
}

void Rev_EncCompare_Helper::set_bit_length(size_t l)
{
    assert(!is_set_up_);
    bit_length_ = l;
    two_l_ = 0;
    mpz_setbit(two_l_.get_mpz_t(),bit_length_); // set two_l_ to 2^l
    comparator_->set_bit_length(l);
}

void Rev_EncCompare_Helper::setup(const mpz_class &c_z)
{
    assert(bit_length_ != 0);
    mpz_class z = paillier_.decrypt(c_z);
    mpz_class d = z % two_l_;
    comparator_->set_value(d);
    
    bool z_l = (bool)mpz_tstbit(z.get_mpz_t(),bit_length_);
    c_z_l_ = comparator_->gm().encrypt(z_l);
    is_set_up_ = true;

//    cout << "Helper setup: \nz = " << z << "\t" << z.get_str(2)<< "\nz_l = " << z_l << "\nd = " << d << endl;

}

void Rev_EncCompare_Helper::decryptResult(const mpz_class &c_t)
{
    is_protocol_done_ = true;
    t_ = comparator_->gm().decrypt(c_t);
}

void runProtocol(Rev_EncCompare_Owner &owner, Rev_EncCompare_Helper &helper, gmp_randstate_t state, unsigned int lambda)
{
    mpz_class c_z(owner.setup(lambda));
    helper.setup(c_z);
    
    runProtocol(owner.comparator(),helper.comparator(),state);
    
    mpz_class c_z_l(helper.get_c_z_l());
    mpz_class c_t(owner.concludeProtocol(c_z_l));
    
    helper.decryptResult(c_t);
}
