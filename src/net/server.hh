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
#include <vector>
#include <boost/asio.hpp>

#include <mpc/garbled_comparison.hh>

#include <FHE.h>

#include <crypto/paillier.hh>
#include <crypto/gm.hh>

#include <net/key_deps_descriptor.hh>
#include <net/defs.hh>

using boost::asio::ip::tcp;

using namespace std;

class Server_session;

class Server {
public:  
    Server(gmp_randstate_t state, Key_dependencies_descriptor key_deps_desc, unsigned int keysize, unsigned int lambda);
    virtual ~Server();
    
    virtual Server_session* create_new_server_session(tcp::socket &socket) = 0;
    void run(const unsigned int port=PORT);
    
    /* Keys management */

    void init_needed_keys(unsigned int keysize);
    void init_GM(unsigned int keysize);
    void init_Paillier(unsigned int keysize);
    void init_FHE_context();
    void init_FHE_key();

    
    Paillier_priv_fast& paillier() { assert(paillier_!=NULL); return *paillier_; };
    vector<mpz_class> paillier_pk() const { assert(paillier_!=NULL); return paillier_->pubkey(); }
    vector<mpz_class> paillier_sk() const { assert(paillier_!=NULL); return paillier_->privkey(); }
    GM_priv& gm() { assert(gm_!=NULL); return *gm_; };
    vector<mpz_class> gm_pk() const { assert(gm_!=NULL); return gm_->pubkey(); }
    vector<mpz_class> gm_sk() const { assert(gm_!=NULL); return {gm_->pubkey()[0],gm_->pubkey()[1],gm_->privkey()[0],gm_->privkey()[1]}; }
    
    const FHESecKey& fhe_sk() const { return *fhe_sk_; } // I don't want anyone to modify the secret key
    const FHEcontext& fhe_context() const { return *fhe_context_; }
    const ZZX& fhe_G() const { return fhe_G_; }
    
    Key_dependencies_descriptor key_deps_desc() const { return key_deps_desc_; }
    
    unsigned int lambda() const { return lambda_; }
    
    unsigned int threads_per_session() const { return threads_per_session_; }
    void set_threads_per_session(unsigned int n) { assert(n > 0); threads_per_session_ = n; }

protected:
    const Key_dependencies_descriptor key_deps_desc_;

    Paillier_priv_fast *paillier_;
    GM_priv *gm_;
    FHEcontext *fhe_context_;
    FHESecKey *fhe_sk_;
    ZZX fhe_G_;

    gmp_randstate_t rand_state_;
    unsigned int n_clients_;
    unsigned int threads_per_session_;
    unsigned int port_;
    
    /* statistical security */
    unsigned int lambda_;
};

class Server_session {
public:
    Server_session(Server *server, gmp_randstate_t state, unsigned int id, tcp::socket &socket);
    virtual ~Server_session();
    
    unsigned int id() const {return id_;}

    virtual void run_session() = 0;
    
    void send_paillier_pk();
    void send_gm_pk();
    void send_fhe_context();
    void send_fhe_pk();
    void get_client_pk_gm();
    void get_client_pk_paillier();
    void get_client_pk_fhe();
    void exchange_keys();

    mpz_class run_comparison_protocol_A(Comparison_protocol_A *comparator);
    mpz_class run_lsic_A(LSIC_A *lsic);
    mpz_class run_priv_compare_A(Compare_A *comparator);
    mpz_class run_garbled_compare_A(GC_Compare_A *comparator);

    void run_comparison_protocol_B(Comparison_protocol_B *comparator);
    void run_lsic_B(LSIC_B *lsic);
    void run_priv_compare_B(Compare_B *comparator);
    void run_garbled_compare_B(GC_Compare_B *comparator);

    bool enc_comparison(const mpz_class &a, const mpz_class &b, size_t l, COMPARISON_PROTOCOL comparison_prot);
    void help_enc_comparison(const size_t &l, COMPARISON_PROTOCOL comparison_prot);
    
    void rev_enc_comparison(const mpz_class &a, const mpz_class &b, size_t l, COMPARISON_PROTOCOL comparison_prot);
    bool help_rev_enc_comparison(const size_t &l, COMPARISON_PROTOCOL comparison_prot);
    
    void rev_enc_comparison_enc_result(const mpz_class &a, const mpz_class &b, size_t l, COMPARISON_PROTOCOL comparison_prot);
    mpz_class help_rev_enc_comparison_enc_result(const size_t &l, COMPARISON_PROTOCOL comparison_prot);
    
    vector<bool> multiple_enc_comparison(const vector<mpz_class> &a, const vector<mpz_class> &b, size_t l, COMPARISON_PROTOCOL comparison_prot);
    void multiple_help_enc_comparison(const size_t n, const size_t &l, COMPARISON_PROTOCOL comparison_prot);

    void multiple_rev_enc_comparison(const vector<mpz_class> &a, const vector<mpz_class> &b, size_t l, COMPARISON_PROTOCOL comparison_prot);
    vector<bool> multiple_help_rev_enc_comparison(const size_t n, const size_t &l, COMPARISON_PROTOCOL comparison_prot);

    mpz_class enc_comparison_enc_result(const mpz_class &a, const mpz_class &b, size_t l, COMPARISON_PROTOCOL comparison_prot);
    void help_enc_comparison_enc_result(const size_t &l, COMPARISON_PROTOCOL comparison_prot);
    
    /* other protocols */
    
    Ctxt change_encryption_scheme(const vector<mpz_class> &c_gm);
    void run_change_encryption_scheme_slots_helper();

    vector<mpz_class> change_encryption_scheme_back(const Ctxt &c_fhe);
    void run_change_encryption_scheme_back_slots_helper();

    vector<mpz_class> change_encryption_scheme_gm_paillier(const vector<mpz_class> &c_gm);
    void run_change_encryption_scheme_gm_paillier_slots_helper();

    vector<mpz_class> change_encryption_scheme_fhe_paillier(const Ctxt &c_fhe);
    void run_change_encryption_scheme_fhe_paillier_slots_helper();

    void move_paillier_to_client(vector<mpz_class> c_p);
    vector<mpz_class> move_paillier_from_client();
    
    mpz_class compute_dot_product(const vector<mpz_class> &x);
    void help_compute_dot_product(const vector<mpz_class> &y, bool encrypted_input = false);

    vector<mpz_class> add_columns(const vector<vector<mpz_class> > &c_p, size_t n_slots);

    /* calls to the comparison owner and helper objects */
    
    bool run_enc_comparison_owner(EncCompare_Owner &owner);
    void run_enc_comparison_helper(EncCompare_Helper &helper);
    void run_rev_enc_comparison_owner(Rev_EncCompare_Owner &owner);
    bool run_rev_enc_comparison_helper(Rev_EncCompare_Helper &helper);
    
    mpz_class run_rev_enc_comparison_owner_enc_result(Rev_EncCompare_Owner &owner);
    void run_rev_enc_comparison_helper_enc_result(Rev_EncCompare_Helper &helper);
    void run_enc_comparison_owner_enc_result(EncCompare_Owner &owner);
    mpz_class run_enc_comparison_helper_enc_result(EncCompare_Helper &helper);

    void run_linear_enc_argmax(Linear_EncArgmax_Helper &helper, COMPARISON_PROTOCOL comparison_prot);
    void run_tree_enc_argmax(Tree_EncArgmax_Helper &helper, COMPARISON_PROTOCOL comparison_prot);
    size_t run_tree_enc_argmax(Tree_EncArgmax_Owner &owner, COMPARISON_PROTOCOL comparison_prot);
    
    /* to build comparators */
    EncCompare_Owner create_enc_comparator_owner(size_t bit_size, COMPARISON_PROTOCOL comparison_prot);
    EncCompare_Helper create_enc_comparator_helper(size_t bit_size, COMPARISON_PROTOCOL comparison_prot);
    Rev_EncCompare_Owner create_rev_enc_comparator_owner(size_t bit_size, COMPARISON_PROTOCOL comparison_prot);
    Rev_EncCompare_Helper create_rev_enc_comparator_helper(size_t bit_size, COMPARISON_PROTOCOL comparison_prot);
    
protected:
    Server *server_;
    tcp::socket socket_;
    boost::asio::streambuf input_buf_;

    GM *client_gm_;
    Paillier *client_paillier_;
    FHEPubKey *client_fhe_pk_;
    gmp_randstate_t rand_state_;
    
    unsigned int id_;
};