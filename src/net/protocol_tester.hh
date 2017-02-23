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

#include <vector>
#include <mpc/lsic.hh>
#include <mpc/private_comparison.hh>
#include <mpc/garbled_comparison.hh>
#include <mpc/enc_comparison.hh>
#include <mpc/rev_enc_comparison.hh>
#include <mpc/linear_enc_argmax.hh>

#include <net/client.hh>
#include <net/server.hh>

#include <proto_src/test_requests.pb.h>

using namespace std;



class  Tester_Server : public Server{
    public:
    Tester_Server(gmp_randstate_t state, unsigned int keysize, unsigned int lambda)
    : Server(state,Tester_Server::key_deps_descriptor(), keysize, lambda) {};
    
    Server_session* create_new_server_session(tcp::socket &socket);
    
    static Key_dependencies_descriptor key_deps_descriptor()
    {
        return Key_dependencies_descriptor(true,true,true,true,true,true);
    }
    
};

class Tester_Client : public Client{
    public:
    Tester_Client(boost::asio::io_service& io_service, gmp_randstate_t state, unsigned int keysize, unsigned int lambda)
    : Client(io_service,state,Tester_Server::key_deps_descriptor(),keysize,lambda) {};
    
    void send_test_query(enum Test_Request_Request_Type type);

    mpz_class test_lsic(const mpz_class &a, size_t l);
    mpz_class test_compare(const mpz_class &b, size_t l);
    mpz_class test_garbled_compare(const mpz_class &b, size_t l);
    
    void test_rev_enc_compare(size_t l);
    void test_enc_compare(size_t l);
    void test_multiple_enc_compare(size_t l);
    void test_linear_enc_argmax();
    void test_tree_enc_argmax();
    void test_fhe();
    void test_change_es();
    void test_ot(unsigned int nOTs);

    void disconnect();
    
    protected:
    size_t bit_size_;
    vector<mpz_class> values_;
    vector<mpz_class> model_;
};

class  Tester_Server_session : public Server_session{
    public:
    
    Tester_Server_session(Tester_Server *server, gmp_randstate_t state, unsigned int id, tcp::socket &socket)
    : Server_session(server,state,id,socket){};
    
    void run_session();
    enum Test_Request_Request_Type get_test_query();

    /* Test functions */
    void test_lsic(const mpz_class &b,size_t l);
    void test_compare(const mpz_class &a,size_t l);
    void test_garbled_compare(const mpz_class &a,size_t l);

    void test_change_es();
    void decrypt_gm(const mpz_class &c);
    void decrypt_fhe();
    void test_ot(unsigned int nOTs);

};
