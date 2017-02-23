/*
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

#include <classifiers/random_forest_classifier.hh>

#include <protobuf/protobuf_conversion.hh>
#include <net/message_io.hh>
#include <net/net_utils.hh>

#include <tree/util.hh>
#include <tree/util_poly.hh>

#include <crypto/paillier.hh>

#include <util/util.hh>

Random_forest_Classifier_Server::Random_forest_Classifier_Server(gmp_randstate_t state, unsigned int keysize, const vector<Node<long>* > &model, unsigned int n_trees, unsigned int n_classes, vector<unsigned int> n_variables, const vector<vector<pair <long,long> > > &criteria, bool majority_vote)
: Server(state, Random_forest_Classifier_Server::key_deps_descriptor(), keysize, 0), n_variables_(n_variables), criteria_(criteria), n_trees_(n_trees), n_classes_(n_classes), majority_vote_(majority_vote)
{
    EncryptedArray ea(*fhe_context_, fhe_G_);

    model_poly_ = vector<Multivariate_poly< vector<long> > >(n_trees);
    for(size_t tj = 0; tj < n_trees; ++tj) {
        model_poly_[tj] = model[tj]->to_polynomial_with_slots(ea.size());
        model_poly_[tj] = mergeRegroup(model_poly_[tj]);
    }

    cout << "Number of slots: " << ea.size() << endl;

}

Server_session* Random_forest_Classifier_Server::create_new_server_session(tcp::socket &socket)
{
    return new Random_forest_Classifier_Server_session(this, rand_state_, n_clients_++, socket);
}


void Random_forest_Classifier_Server_session::run_session()
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

        vector<vector<pair <long,long> > > criteria = forest_server_->criteria();

        vector<vector<mpz_class> > node_values(forest_server_->n_trees()); // do it for every tree

        t = new ScopedTimer("Server: Compute node values for every tree and node");
        // for all trees, get necessary criteria
        for(size_t tj = 0; tj < node_values.size(); ++tj) {
            node_values[tj] = vector<mpz_class>(forest_server_->n_variables(tj));
            for (size_t i = 0; i < node_values[tj].size(); ++i) {
                // remove unnecessary dot product
                node_values[tj][i] = query[get<0>(criteria[tj][i])]; // client_paillier_->dot_product(query, get<0>(criteria[i]));
            }
        }
        delete t;

        // compare all values
        vector<vector<mpz_class> > c_b_gm(forest_server_->n_trees());
        
        t = new ScopedTimer("Server: Compare");
        for(size_t tj = 0; tj < c_b_gm.size(); ++tj) {
            c_b_gm[tj] = vector<mpz_class>(forest_server_->n_variables(tj));
            for (size_t i = 0; i < c_b_gm[tj].size(); ++i) {
                mpz_class c_treshold = client_paillier_->encrypt(get<1>(criteria[tj][i]));
                c_b_gm[tj][i] = enc_comparison_enc_result(node_values[tj][i], c_treshold, 128, GC_PROTOCOL);
            }
        }
        delete t;

        // convert
        vector<vector<Ctxt> > c_b_fhe(forest_server_->n_trees());

        t = new ScopedTimer("Server: Change encryption scheme");
        for(size_t tj = 0; tj < c_b_fhe.size(); ++tj) {
            for (size_t i = 0; i < forest_server_->n_variables(tj); ++i) {
                // duplicate everything
                vector<mpz_class> duplicates(ea.size(), c_b_gm[tj][i]);
                c_b_fhe[tj].push_back(change_encryption_scheme(duplicates));
            }
        }
        delete t;

        // evaluate the polynomial
        vector<Ctxt> c_r;

        t = new ScopedTimer("Server: Evaluation");
        for(size_t tj = 0; tj < forest_server_->n_trees(); ++tj) {
            if(forest_server_->model_poly(tj).degree() > FHE_L) {
                cerr << "L parameter of FHE scheme is too small (" << FHE_L << ", but " << forest_server_->model_poly(tj).degree() << " multiplications needed)" << endl;
            }
            c_r.push_back(evalPoly_FHE(forest_server_->model_poly(tj), c_b_fhe[tj], ea, useShallowCircuit));
        }
        delete t;

        if(forest_server_->majority_vote()) {
            cout << "Performing majority vote protocol." << endl;

            // change back encryption scheme
            vector<vector<mpz_class> > c_r_p(forest_server_->n_trees());

            t = new ScopedTimer("Server: Change encryption scheme back");
            // this part is inefficient, since we probably have encryptions of all slots
            for (size_t tj = 0; tj < c_b_fhe.size(); ++tj) {
                Ctxt d(c_r[tj]);
                c_r_p[tj] = change_encryption_scheme_fhe_paillier(d);
            }
            delete t;

            assert(forest_server_->n_trees() > 0);
            size_t n_slots = forest_server_->n_classes(); // now only work with those slots we need
            // add all values
            t = new ScopedTimer("Server: Compute class counts");
            vector<mpz_class> c_p_counts = add_columns(c_r_p, n_slots);
            delete t;

            // move encryptions to client
            t = new ScopedTimer("Server: Move encryptions to client");
            move_paillier_to_client(c_p_counts);
            delete t;

            // perform argmax
            t = new ScopedTimer("Server: Reveal argmax to client");
            Tree_EncArgmax_Helper helper(54 + max_bits(forest_server_->n_trees()), c_p_counts.size(),
                                         forest_server_->paillier());
            run_tree_enc_argmax(helper, GC_PROTOCOL);
            delete t;
        } else {
            cout << "Sending plain data." << endl;

            t = new ScopedTimer("Server: Sending results to the client");
            for (size_t tj = 0; tj < forest_server_->n_trees(); ++tj) {
                send_fhe_ctxt_to_socket(socket_, c_r[tj]);
            }
            delete t;
        }

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

Random_forest_Classifier_Client::Random_forest_Classifier_Client(boost::asio::io_service& io_service, gmp_randstate_t state, unsigned int keysize, vector<long> &query, vector<unsigned int> n_nodes, unsigned int n_trees, unsigned int n_classes, bool majority_vote)
: Client(io_service,state,Random_forest_Classifier_Server::key_deps_descriptor(),keysize,100), query_(query), n_nodes_(n_nodes), n_trees_(n_trees), n_classes_(n_classes), majority_vote_(majority_vote)
{
    
}

void Random_forest_Classifier_Client::run()
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
    for (unsigned int tj = 0; tj < n_trees_; ++tj) {
        for (unsigned int i = 0; i < n_nodes_[tj]; ++i) {
            // for now, do it over 64 bits
            help_enc_comparison_enc_result(128, GC_PROTOCOL);
        }
    }
    delete t;

    t = new ScopedTimer("Client: Change encryption scheme");
    // now he wants the booleans encrypted under FHE
    for (unsigned int tj = 0; tj < n_trees_; ++tj) {
        for (unsigned int i = 0; i < n_nodes_[tj]; i++) {
            run_change_encryption_scheme_slots_helper();
        }
    }
    delete t;

    long v = 0;

    if (majority_vote_) {
        cout << "Performing majority vote protocol." << endl;

        t = new ScopedTimer("Client: Change encryption scheme back");
        for (unsigned int tj = 0; tj < n_trees_; ++tj) {
            run_change_encryption_scheme_fhe_paillier_slots_helper();
        }
        delete t;

        // get encryptions from client
        t = new ScopedTimer("Client: Move encryptions from client");
        vector<mpz_class> c_p_counts = move_paillier_from_server();
        delete t;

        t = new ScopedTimer("Client: Compute argmax");
        Tree_EncArgmax_Owner owner(c_p_counts, 54 + max_bits(n_trees_), *server_paillier_, rand_state_);
        v = run_tree_enc_argmax(owner, GC_PROTOCOL);
        delete t;
    } else {
        cout << "Receiving plain data." << endl;

        t = new ScopedTimer("Client: Receiving data from server");
        vector<Ctxt> c_r;
        for (size_t tj = 0; tj < n_trees_; ++tj) {
            c_r.push_back(read_fhe_ctxt_from_socket(socket_, *fhe_sk_));
        }
        delete t;

        t = new ScopedTimer("Client: Decrypt result");
        for (size_t tj = 0; tj < n_trees_; ++tj) {
            vector<long> res_bits;
            ea.decrypt(c_r[tj], *fhe_sk_, res_bits);

            cout << "Tree " << tj << endl;
            cout << bitSet_inv(res_bits) << endl;
            v += bitSet_inv(res_bits);
        }
        v /= n_trees_;
        delete t;
    }
    
#ifdef BENCHMARK
    cout << "Benchmark: " << GET_BENCHMARK_COMP_TIME << " ms (computation)" << endl;
    cout << "Benchmark: " << GET_BENCHMARK_NET_TIME << " ms (network)" << endl;
    cout << (IOBenchmark::byte_count()/to_kB) << " exchanged kB" << endl;
    cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif

    cout << "Classification result: " << v << endl;
}


