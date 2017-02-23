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

#include <classifiers/decision_tree_classifier.hh>

#include <protobuf/protobuf_conversion.hh>
#include <net/message_io.hh>
#include <net/net_utils.hh>

#include <tree/util.hh>
#include <tree/util_poly.hh>

#include <util/util.hh>

Decision_tree_Classifier_Server::Decision_tree_Classifier_Server(gmp_randstate_t state, unsigned int keysize, const Tree<long> &model, unsigned int n_variables, const vector<pair <vector<long>,long> > &criteria)
: Server(state, Decision_tree_Classifier_Server::key_deps_descriptor(), keysize, 0), n_variables_(n_variables), criteria_(criteria)
{
    EncryptedArray ea(*fhe_context_, fhe_G_);
    model_poly_ = model.to_polynomial_with_slots(ea.size());
    model_poly_ = mergeRegroup(model_poly_);

}

Server_session* Decision_tree_Classifier_Server::create_new_server_session(tcp::socket &socket)
{
    return new Decision_tree_Classifier_Server_session(this, rand_state_, n_clients_++, socket);
}

//void Decision_tree_Classifier_Server_session::run_session()
//{
//    try {
//        exchange_keys();
//        
//        // get the query
//        vector<Ctxt> query;
//        for (size_t i = 0; i < tree_server_->n_variables() ; i++) {
//            query.push_back(read_fhe_ctxt_from_socket(socket_, *client_fhe_pk_));
//        }
//        
//        
//        
//        bool useShallowCircuit = true;
//        EncryptedArray ea(server_->fhe_context(), server_->fhe_G());
//        
//        // evaluate the polynomial
//        Ctxt c_r = evalPoly_FHE(tree_server_->model_poly(), query,ea,useShallowCircuit);
//        
//        // send the result back to the client
//        send_fhe_ctxt_to_socket(socket_, c_r);
//        
//    } catch (std::exception& e) {
//        std::cout << "Exception: " << e.what() << std::endl;
//    }
//    
//    delete this;
//}

void Decision_tree_Classifier_Server_session::run_session()
{
    try {
        exchange_keys();
        
        bool useShallowCircuit = true;
        EncryptedArray ea(server_->fhe_context(), server_->fhe_G());

        ScopedTimer *t;
        RESET_BYTE_COUNT
        RESET_BENCHMARK_TIMER

        // get the query
        vector<mpz_class> query;
        query = read_int_array_from_socket(socket_);
        
        vector<pair <vector<long>,long> > criteria = tree_server_->criteria();

        vector<mpz_class> node_values(tree_server_->n_variables());
        
        t = new ScopedTimer("Server: Compute dot product");
        // compute all the dot products
        for (size_t i = 0; i < node_values.size(); i++) {
            node_values[i] = client_paillier_->dot_product(query, get<0>(criteria[i]));
        }
        delete t;

        // compare
        vector<mpz_class> c_b_gm(tree_server_->n_variables());
        
        t = new ScopedTimer("Server: Compare");
        for (size_t i = 0; i < node_values.size(); i++) {
            mpz_class c_treshold = client_paillier_->encrypt(get<1>(criteria[i]));
            c_b_gm[i] = enc_comparison_enc_result(node_values[i],c_treshold,64,GC_PROTOCOL);
        }
        delete t;

        // convert
        vector<Ctxt> c_b_fhe;

        t = new ScopedTimer("Server: Change encryption scheme");
        for (size_t i = 0; i < node_values.size(); i++) {
            // duplicate everything
            vector<mpz_class> duplicates(ea.size(),c_b_gm[i]);
            c_b_fhe.push_back(change_encryption_scheme(duplicates));
        }
        delete t;

        // evaluate the polynomial

        t = new ScopedTimer("Server: Evaluation");
        Ctxt c_r = evalPoly_FHE(tree_server_->model_poly(), c_b_fhe,ea,useShallowCircuit);
        delete t;
        
        // send the result back to the client
        send_fhe_ctxt_to_socket(socket_, c_r);

#ifdef BENCHMARK
        cout << "Benchmark: " << GET_BENCHMARK_COMP_TIME << " ms (computation)" << endl;
        cout << "Benchmark: " << GET_BENCHMARK_NET_TIME << " ms (network)" << endl;
        cout << IOBenchmark::byte_count() << " exchanged bytes" << endl;
        cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif

        
    } catch (std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    
    delete this;
}

Decision_tree_Classifier_Client::Decision_tree_Classifier_Client(boost::asio::io_service& io_service, gmp_randstate_t state, unsigned int keysize, vector<long> &query, unsigned int n_nodes)
: Client(io_service,state,Decision_tree_Classifier_Server::key_deps_descriptor(),keysize,0), query_(query), n_nodes_(n_nodes)
{
    
}

//void Decision_tree_Classifier_Client::run()
//{
//    exchange_keys();
//    
//    EncryptedArray ea(*fhe_context_, fhe_G_);
//
//    vector<PlaintextArray> b(query_.size(),PlaintextArray(ea));
//    vector<Ctxt> c_b(query_.size(),Ctxt(*fhe_sk_));
//    
//    for (size_t i = 0; i < query_.size(); i++) {
//        b[i].encode(query_[i]);
//        ea.encrypt(c_b[i],*fhe_sk_,b[i]);
//    }
//
//    // send the query to the server ...
//    for (size_t i = 0; i < query_.size(); i++) {
//        send_fhe_ctxt_to_socket(socket_, c_b[i]);
//    }
//    
//    // ... and wait for the result
//    Ctxt c_r = read_fhe_ctxt_from_socket(socket_,*fhe_sk_);
//    
//    // decrypt and test
//    vector<long> res_bits;
//    ea.decrypt(c_r, *fhe_sk_, res_bits);
//    
//    for (size_t i = 0; i < query_.size(); i++) {
//        assert(res_bits[i] == query_[i]);
//    }
//    
//    cout << "Test passed!" << endl;
//
//}

void Decision_tree_Classifier_Client::run()
{
    RESET_BYTE_COUNT
    exchange_keys();
#ifdef BENCHMARK
    const double to_kB = 1 << 10;
    cout << "Key exchange: " <<  (IOBenchmark::byte_count()/to_kB) << " kB" << endl;
    cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif

    EncryptedArray ea(*fhe_context_, fhe_G_);

    ScopedTimer *t;
    RESET_BYTE_COUNT
    RESET_BENCHMARK_TIMER

    // send our query encrypted under paillier
    vector<mpz_class> enc_query(query_.size());
    for (size_t i = 0; i < query_.size(); i++) {
        enc_query[i] = paillier_->encrypt(query_[i]);
    }
    
    send_int_array_to_socket(socket_,enc_query);
    
    // the server computes the criteria for each node and needs our help
    
    t = new ScopedTimer("Client: Compute criteria");

    for (unsigned int i = 0; i < n_nodes_; i++) {
        // for now, do it over 64 bits
        help_enc_comparison_enc_result(64, GC_PROTOCOL);
    }
    delete t;

    t = new ScopedTimer("Client: Change encryption scheme");
    // now he wants the booleans encrypted under FHE
    for (unsigned int i = 0; i < n_nodes_; i++) {
        run_change_encryption_scheme_slots_helper();
    }
    delete t;
    
    // we get the result and decrypt it
    Ctxt c_r = read_fhe_ctxt_from_socket(socket_,*fhe_sk_);
    // decrypt and test
    vector<long> res_bits;
    t = new ScopedTimer("Client: Decrypt result");
    ea.decrypt(c_r, *fhe_sk_, res_bits);

    long v = bitSet_inv(res_bits);
    delete t;

#ifdef BENCHMARK
    cout << "Benchmark: " << GET_BENCHMARK_COMP_TIME << " ms (computation)" << endl;
    cout << "Benchmark: " << GET_BENCHMARK_NET_TIME << " ms (network)" << endl;
    cout << (IOBenchmark::byte_count()/to_kB) << " exchanged kB" << endl;
    cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif

    cout << "Classification result: " << v << " " << res_bits.size() << endl;
}


