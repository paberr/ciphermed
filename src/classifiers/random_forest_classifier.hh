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

#pragma once

#include <vector>
#include <mpc/lsic.hh>
#include <mpc/private_comparison.hh>
#include <mpc/enc_comparison.hh>
#include <mpc/rev_enc_comparison.hh>
#include <mpc/linear_enc_argmax.hh>
#include <mpc/tree_enc_argmax.hh>

#include <net/client.hh>
#include <net/server.hh>

#include <tree/tree.hh>
#include <tree/m_variate_poly.hh>

#include <utility>

using namespace std;

#define N_LEVELS 3

class Random_forest_Classifier_Server : public Server {
public:
    Random_forest_Classifier_Server(gmp_randstate_t state, unsigned int keysize, const vector<Node<long>* > &model, unsigned int n_trees, unsigned int n_classes, vector<unsigned int> n_variables, const vector<vector<pair <long,long> > > &criteria, bool majority_vote);
  
    Server_session* create_new_server_session(tcp::socket &socket);

    static Key_dependencies_descriptor key_deps_descriptor()
    {
        return Key_dependencies_descriptor(true,true,false,true,true,true);
    }

    Multivariate_poly< vector<long> > model_poly(const int tree) const { return model_poly_[tree]; }
    unsigned int n_variables(const int tree) { return n_variables_[tree]; }
    unsigned int n_trees() const { return n_trees_; }
    unsigned int n_classes() const { return n_classes_; }
    bool majority_vote() const { return majority_vote_; }
    vector<vector<pair <long,long> >> criteria() const { return criteria_; }

protected:
    vector<Multivariate_poly< vector<long> > > model_poly_;
    const vector<unsigned int> n_variables_;
    const unsigned int n_trees_;
    const unsigned int n_classes_;
    const bool majority_vote_;
    vector<vector<pair <long,long> > > criteria_;
};


class  Random_forest_Classifier_Server_session : public Server_session{
public:
    
    Random_forest_Classifier_Server_session(Random_forest_Classifier_Server *server, gmp_randstate_t state, unsigned int id, tcp::socket &socket)
    : Server_session(server,state,id,socket), forest_server_(server) {};
    
    void run_session();
    
protected:
    Random_forest_Classifier_Server *forest_server_;
};

class Random_forest_Classifier_Client : public Client{
public:
    Random_forest_Classifier_Client(boost::asio::io_service& io_service, gmp_randstate_t state, unsigned int keysize, vector<long> &query, vector<unsigned int> n_nodes, unsigned int n_trees,
                                    unsigned int n_classes, bool majority_vote);
    
    void run();
    
protected:
    vector<long> query_;
    vector<unsigned int> n_nodes_;
    const unsigned int n_classes_;
    const unsigned int n_trees_;
    const bool majority_vote_;
};
