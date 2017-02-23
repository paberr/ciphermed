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
#include <util/benchmarks.hh>

#define     VF  0
#define     VT  1
#define     SVT  2
#define     PVC  3
#define     NSR  4
#define     APC  5

static Node<long>* model_ecg1(vector<pair <long,long> > &criteria )
{
    criteria = vector<pair <long,long> >(6);
    //                                feature, comparison value
    criteria[0] = make_pair<long,long>(0,0);
    criteria[1] = make_pair<long,long>(1,0);
    criteria[2] = make_pair<long,long>(2,0);
    criteria[3] = make_pair<long,long>(3,0);
    criteria[4] = make_pair<long,long>(4,0);
    criteria[5] = make_pair<long,long>(0,0);

    Node<long> *n_left = new Node<long>(4,new Leaf<long>(PVC), new Leaf<long>(NSR));
    Node<long> *n_right = new Node<long>(5,new Leaf<long>(NSR), new Leaf<long>(APC));
   
    n_right = new Node<long>(3, n_left, n_right);
    n_right = new Node<long>(2, new Leaf<long>(SVT), n_right);
    
    n_left = new Node<long>(1,new Leaf<long>(VF), new Leaf<long>(VT));
    
    return new Node<long>(0, n_left, n_right);
}

static Node<long>* model_ecg2(vector<pair <long,long> > &criteria )
{
    criteria = vector<pair <long,long> >(8);

    criteria[0] = make_pair<long,long>(4,0);
    criteria[1] = make_pair<long,long>(1,0);
    criteria[2] = make_pair<long,long>(3,0);
    criteria[3] = make_pair<long,long>(2,0);
    criteria[4] = make_pair<long,long>(0,0);
    criteria[5] = make_pair<long,long>(1,0);
    criteria[6] = make_pair<long,long>(3,0);
    criteria[7] = make_pair<long,long>(2,0);

    Node<long> *n_left = new Node<long>(4,new Leaf<long>(PVC), new Leaf<long>(NSR));
    Node<long> *n_right = new Node<long>(5,new Leaf<long>(NSR), new Leaf<long>(APC));

    n_right = new Node<long>(3, n_left, n_right);
    n_right = new Node<long>(2, new Node<long>(6,new Leaf<long>(VF), new Leaf<long>(SVT)), n_right);

    n_left = new Node<long>(1,new Leaf<long>(VF), new Node<long>(7,new Leaf<long>(PVC), new Leaf<long>(NSR)));

    return new Node<long>(0, n_left, n_right);
}

static void test_tree_classifier_server()
{
    gmp_randstate_t randstate;
    gmp_randinit_default(randstate);
    gmp_randseed_ui(randstate,time(NULL));

    vector<vector<pair <long,long> > > criteria(3);
    vector<unsigned int> n_nodes(3);

    n_nodes[0] = 6;
    n_nodes[1] = 6;
    n_nodes[2] = 8;
    
    
#ifdef BENCHMARK
    cout << "BENCHMARK flag set" << endl;
    BENCHMARK_INIT
#endif

    vector<Node<long>* > trees;

    cout << "Tree 1" << endl;
    Node<long> *t;
    t = model_ecg1(criteria[0]);
    trees.push_back(t);
    cout << "Tree 2" << endl;
    Node<long> *t1;
    t1 = model_ecg1(criteria[1]);
    trees.push_back(t1);
    cout << "Tree 3" << endl;
    Node<long> *t2;
    t2 = model_ecg2(criteria[2]);
    trees.push_back(t2);

    cout << "Init server" << endl;
    Random_forest_Classifier_Server server(randstate,1248,trees,trees.size(),6,n_nodes, criteria, true);
    
    cout << "Start server" << endl;
    server.run();
}

int main()
{    
    test_tree_classifier_server();
    
    return 0;
}
