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

#include <util/util.hh>
#include <util/benchmarks.hh>

static vector<long> gen_nursery_query()
{
    vector<long> query(8);
    
    query[0] = 1 + (rand() %3);
    query[1] = 1 + (rand() %5);
    query[2] = 1 + (rand() %4);
    query[3] = 1 + (rand() %4);
    query[4] = 1 + (rand() %3);
    query[5] = 1 + (rand() %2);
    query[6] = 1 + (rand() %3);
    query[7] = 1 + (rand() %3);
    
    return query;
}

static vector<long> gen_ecg_query()
{
    vector<long> query(5);
    long modulo = 1; // 2^44
    modulo <<= 44;
    
//    query[0] = (1-2*(rand()%2)) * (rand() % modulo);
//    query[1] = (1-2*(rand()%2)) * (rand() % modulo);
//    query[2] = (1-2*(rand()%2)) * (rand() % modulo);
//    query[3] = (1-2*(rand()%2)) * (rand() % modulo);
//    query[4] = (1-2*(rand()%2)) * (rand() % modulo);

    query[0] = 52334;
    query[1] = 3241;
    query[2] = 13425;
    query[3] = 5354;
    query[4] = 1345;
    
    return query;

}

static void test_tree_classifier_client(const string &hostname)
{
    try
    {
#ifdef BENCHMARK
        cout << "BENCHMARK flag set" << endl;
        BENCHMARK_INIT
#endif
        
   
        boost::asio::io_service io_service;
        
        gmp_randstate_t randstate;
        gmp_randinit_default(randstate);
        gmp_randseed_ui(randstate,time(NULL));


        vector<long> query;
        unsigned int n_nodes = 20;
        unsigned int n_trees = 3;
        
//       query = gen_nursery_query();
//       n_nodes = 4;
        
        query = gen_ecg_query();
        
        
//        vector<long> query_bits = bitDecomp(query, N_LEVELS);
        Random_forest_Classifier_Client client(io_service, randstate,1248,query,n_nodes,n_trees, 6, true);
        
        client.connect(io_service, hostname);
        
        client.run();
        
//        client.disconnect();
        
    }
    catch (std::exception& e)
    {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: client <host>" << std::endl;
        return 1;
    }
    string hostname(argv[1]);
    srand(time(NULL));

    test_tree_classifier_client(hostname);
    
    return 0;
}