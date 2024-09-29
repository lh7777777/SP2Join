#ifndef _BIGSI_
#define _BIGSI_
#include <vector>
#include <set>
#include <cstring>
#include <random>

// #include <iostream>
#include <algorithm>
#include <set>
#include <chrono>

#include "BloomFilter.h"
#include "MurmurHash3.h"

// using namespace std;

class BIGSI
{
public:
    // BIGSI(int m, int k,  size_t total_usage);
    // void insertion(int setID, std::string keys);
    // // std::int16_t query(size_t setID,std::string query_key);
    // std::vector<bool> query(size_t s1,size_t s2);
    // // std::set<size_t> query(std::string query_key);

    BIGSI(int m, int k, size_t total_usage)
    {

        this->num_sets = m;
        this->capacity = total_usage;
         this->single_capacity = size_t(this->capacity / 2);
        this->k = k;
        this->time = 0.0;
        this->total_hash_num = 0;

        Bigsi_array = new BloomFilter *[this->num_sets];
        for (int i = 0; i < this->num_sets; i++)
        {
            Bigsi_array[i] = new BloomFilter(this->single_capacity, this->k);
        }

        this->seed = new size_t[this->k];

        // random_device bf;
        // mt19937 seed_ge(bf());
        // uniform_int_distribution<size_t> dis(0, 10000000);
        // for(int i = 0; i < this->k; i++){
        //     this->seed[i] = dis(seed_ge);
        // }

        // Generate k random numbers using sgx_read_rand
        for (int i = 0; i < this->k; i++)
        {
            size_t generatedNumber;
            // sgx_status_t status;
            if ((sgxssl_read_rand(reinterpret_cast<uint8_t *>(&generatedNumber), sizeof(generatedNumber))) != SGX_SUCCESS)
            {
                printf("Failed to generate random number");
            }
            this->seed[i] = generatedNumber;
        }
    }

    void insertion(int setID, string keys)
    {
        // printf("goto the insert function\n");
        vector<size_t> locations = BF_Hash(keys, this->k, this->seed, this->single_capacity);
        // Bigsi_array[stoi(setID)]->insert(locations);
        Bigsi_array[setID]->insert(locations);
        this->total_hash_num += locations.size();
    }

    vector<bool> query(size_t s1, size_t s2)
    {

        size_t res_set = 1;
        std::vector<bool> Cmp_Array(this->single_capacity);
        // vector<size_t> check_locations = BF_Hash(query_key, this->k, this->seed, this->single_capacity);
        for (size_t i = 0; i < this->single_capacity; i++)
        {
            std::vector<size_t> indices = {i};
            bool bit_result = Bigsi_array[s1]->check(indices) & Bigsi_array[s2]->check(indices);
            Cmp_Array[i] = bit_result;
        }
        return Cmp_Array;
    }

    int16_t obfmtquery(size_t setID, std::string query_key)
    {

        int res_set = 0;
        vector<int> testvector(this->single_capacity, 0);
        vector<size_t> check_locations = BF_Hash(query_key, this->k, this->seed, this->single_capacity);

        for (int i = 0; i < check_locations.size(); i++)
        {
            for (int j = 0; j < this->single_capacity; j++)
            {
                testvector[j] = testvector[j] ^ (check_locations[i] == j);
            }
        }

        for (size_t i = 0; i < this->single_capacity; i++)
        {
            std::vector<size_t> indices = {i};
            testvector[i] = testvector[i] & Bigsi_array[setID]->check(indices);
            res_set += testvector[i];
        }

        if (res_set - this->k == 0)
            return true;
        else
            return false;
    }

    int num_sets;
    int k;
    size_t capacity;
    size_t single_capacity;
    float time;
    size_t *seed;
    int total_hash_num;

    BloomFilter **Bigsi_array;
};

#endif