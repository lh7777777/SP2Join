/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave_t.h" /* print_string */
#include "baddtree.h"
#include "data_ebuffer.h"
#include "encode.h"
#include "kdtree.h"
#include "BloomFilter.h"
#include "BIGSI.h"
#include "CSCBF.h"
#include "Ocall_wrappers.h"
#include "ObliviousSort.h"

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <map>
#include <vector>
#include <time.h>

#include <functional>
#include <memory>
#include <unordered_map>

using namespace BAT;

string cbc_key1 = "12345678901234561234567890123456";
string cbc_key2 = "98765432101234569876543210123456";
string iv0 = "1000000000000000";
string iv1 = "1111111111111111";
string iv2 = "2000000000000000";
string iv3 = "2111111111111111";
string iv4 = "3000000000000000";
string iv5 = "3111111111111111";
string iv6 = "4000000000000000";
string iv7 = "4111111111111111";
string iv8 = "5000000000000000";
string iv9 = "5111111111111111";
long long liv1 = atoll(iv0.c_str());

#define HASH_NUM 3
#define REP_TIME 3
#define PART_NUM 62
#define TOTAL_CAP 60000

BAddTree<int, k_r> *tree;

void ecall_init(int order)
{
    printf("ecall_init\n");
    for (int i = 1; i <= EBUFFER_SIZE; i++)
    {
        MBuf_id mbuf_id;
        mbuf_id.page_id = (i - 1) / 4 + 1;
        mbuf_id.offset = (i - 1) % 4;
        node2page[i] = mbuf_id;
    }
    for (int i = 0; i < 16; i++)
    {
        key[i] = 32 + i;
    }

    tree = new BAddTree<int, k_r>(order);
}

int ecall_search(int key, void *mbdes, char **mbpool)
{
    printf("ecall_search\n");
    return tree->find(key, (MBuf_des *)mbdes, mbpool)->rid;
}

void ecall_insert(void *key_rid, void *mbdes, char **mbpool)
{
    printf("ecall_insert\n");
    k_r *kr = (k_r *)key_rid;
    tree->insert(*kr, (MBuf_des *)mbdes, mbpool);
}

auto itf = [&](deque<k_r *> &e)
{
    int _s = e.size();
    for (int i = 0; i < _s; ++i)
    {
        printf("%d ", e[i]->k);
    }
};

void ecall_traversal()
{
    printf("ebuffer size: %d\n", tree->ebuffer->size);
    printf("tree size: %d\n", tree->size());
    printf("start traversal:\n");
    tree->list_traversal(itf);
}

Data_EBuffer *Def;
Data_EBuffer *Def1;

void ecall_data_init()
{
    printf("ecall_data_init\n");

    for (int i = 0; i < 16; i++)
    {
        key2[i] = 32 + i;
    }

    Def = new Data_EBuffer(-1);
}
char *ecall_data_search(int rid, void *mbdes, char **mbpool)
{
    printf("ecall_data_search\n");
    return Def->SearchData(rid, (MBuf_des *)mbdes, mbpool);
}

void ecall_data_insert(char *newdata, void *mbdes, char **mbpool)
{
    printf("ecall_data_insert\n");
    Def->InsertData(newdata, (MBuf_des *)mbdes, mbpool);
}

void ecall_joinsearch1(char **ein0, char **ein1, char **ein2, char **ein3, char **ein4, char **ein5, char **ein6, char **ein7, char **ein8, char **ein9, void *mbdes, char **mbpool)
{

    clock_t s2, e2;
    s2 = sgx_clock();

    ocall_open_result();
    ocall_open_enquery();

    char *enumber = new char[25];
    ocall_read_s(enumber, 25);
    string senumber = enumber;
    string number_decode_base64 = base64_decode(senumber);
    string sn = aes_256_cbc_decode(cbc_key1, iv0, number_decode_base64);
    int num = atoi(sn.c_str());
    printf("num:%d \n", num);
    liv1++;

    vector<int> table;
    for (int i = 0; i < num; i++)
    {
        char *en = new char[25];
        ocall_read_s(en, 25);
        string sen = en;
        string niv1 = to_string(liv1);
        liv1++;
        string n_decode_base64 = base64_decode(sen);
        string n = aes_256_cbc_decode(cbc_key1, niv1, n_decode_base64);
        table.push_back(atoi(n.c_str()));
    }

    int len0 = 0;

    ocall_read_eneq0(&len0, ein0);

    int len1 = 0;

    ocall_read_eneq1(&len1, ein1);

    BIGSI baseline_bigsi(num, HASH_NUM, TOTAL_CAP);
    vector<pair<int, int>> storage2;

    if (num == 2)
    {
        vector<string> index0;
        vector<string> index1;
        map<string, int> result0;
        map<string, int> result1;

        for (int p0 = 0; p0 < len0; p0++)
        {
            string enindex0 = ein0[p0];
            string p0_decode_base64 = base64_decode(enindex0);
            string p0_decode = aes_256_cbc_decode(cbc_key2, iv0, p0_decode_base64);
            index0.push_back(p0_decode);
            baseline_bigsi.insertion(0, p0_decode);
        }

        for (int p1 = 0; p1 < len1; p1++)
        {
            string enindex1 = ein1[p1];
            string p1_decode_base64 = base64_decode(enindex1);
            string p1_decode = aes_256_cbc_decode(cbc_key2, iv1, p1_decode_base64);
            index1.push_back(p1_decode);
            baseline_bigsi.insertion(1, p1_decode);
        }

        std::vector<bool> Cmp_Array(baseline_bigsi.single_capacity, false);
        Cmp_Array = baseline_bigsi.query(0, 1);

        for (int i = 0; i < index1.size(); i++)
        {
            int res = 1;
            vector<size_t> check_locations = BF_Hash(index1[i], baseline_bigsi.k, baseline_bigsi.seed, baseline_bigsi.single_capacity);
            for (auto &location : check_locations)
            {
                res &= Cmp_Array[location];
            }
            if (res)
            {
                result1[index1[i]] = i;
            }
        }
        for (int j = 0; j < index0.size(); j++)
        {
            if (result1.find(index0[j]) != result1.end())
                result0[index0[j]] = j;
        }

        unordered_map<string, int> HTE;
        for (auto h1 : result0)
        {
            HTE[h1.first] = h1.second;
        }
        for (auto h2 : result1)
        {
            if (HTE.find(h2.first) != HTE.end())
            {
                storage2.push_back(pair<int, int>(HTE[h2.first], h2.second));
            }
        }
    }

    if (num == 3)
    {
        int len2 = 0;
        ocall_read_eneq2(&len2, ein2);
        vector<int> lens = {len1, len2};
        vector<string> ivs = {iv1, iv2};
        vector<string> index0;

        for (int p0 = 0; p0 < len0; p0++)
        {
            string enindex0 = ein0[p0];
            string p0_decode_base64 = base64_decode(enindex0);
            string p0_decode = aes_256_cbc_decode(cbc_key2, iv0, p0_decode_base64);
            index0.push_back(p0_decode);
            baseline_bigsi.insertion(0, p0_decode);
        }

        for (int tbl = 0; tbl < 2; tbl++)
        {
            vector<string> index1;
            map<string, int> result0;
            map<string, int> result1;

            for (int p1 = 0; p1 < lens[tbl]; p1++)
            {
                string enindex1;
                if (tbl == 0)
                {
                    enindex1 = ein1[p1];
                }
                if (tbl == 1)
                {
                    enindex1 = ein2[p1];
                }

                string p1_decode_base64 = base64_decode(enindex1);
                string p1_decode = aes_256_cbc_decode(cbc_key2, ivs[tbl], p1_decode_base64);
                index1.push_back(p1_decode);
                baseline_bigsi.insertion(tbl + 1, p1_decode);
            }

            std::vector<bool> Cmp_Array(baseline_bigsi.single_capacity, false);
            Cmp_Array = baseline_bigsi.query(0, tbl + 1);

            for (int i = 0; i < index1.size(); i++)
            {
                int res = 1;
                vector<size_t> check_locations = BF_Hash(index1[i], baseline_bigsi.k, baseline_bigsi.seed, baseline_bigsi.single_capacity);
                for (auto &location : check_locations)
                {
                    res &= Cmp_Array[location];
                }
                if (res)
                {
                    result1[index1[i]] = i;
                }
            }
            for (int j = 0; j < index0.size(); j++)
            {
                if (result1.find(index0[j]) != result1.end())
                    result0[index0[j]] = j;
            }

            unordered_map<string, int> HTE;
            for (auto h1 : result0)
            {
                HTE[h1.first] = h1.second;
            }
            for (auto h2 : result1)
            {
                if (HTE.find(h2.first) != HTE.end())
                {
                    storage2.push_back(pair<int, int>(HTE[h2.first], h2.second));
                }
            }
        }
    }

    if (num == 5)
    {

        int len2 = 0, len3 = 0, len4 = 0;
        ocall_read_eneq2(&len2, ein2);
        ocall_read_eneq3(&len3, ein3);
        ocall_read_eneq4(&len4, ein4);
        vector<int> lens = {len1, len2, len3, len4};
        vector<string> ivs = {iv1, iv2, iv3, iv4};
        vector<string> index0;

        for (int p0 = 0; p0 < len0; p0++)
        {
            string enindex0 = ein0[p0];
            string p0_decode_base64 = base64_decode(enindex0);
            string p0_decode = aes_256_cbc_decode(cbc_key2, iv0, p0_decode_base64);
            index0.push_back(p0_decode);
            baseline_bigsi.insertion(0, p0_decode);
        }

        for (int tbl = 0; tbl < 4; tbl++)
        {
            vector<string> index1;
            map<string, int> result0;
            map<string, int> result1;

            for (int p1 = 0; p1 < lens[tbl]; p1++)
            {
                string enindex1;
                if (tbl == 0)
                {
                    enindex1 = ein1[p1];
                }
                if (tbl == 1)
                {
                    enindex1 = ein2[p1];
                }
                if (tbl == 2)
                {
                    enindex1 = ein3[p1];
                }
                if (tbl == 3)
                {
                    enindex1 = ein4[p1];
                }

                string p1_decode_base64 = base64_decode(enindex1);
                string p1_decode = aes_256_cbc_decode(cbc_key2, ivs[tbl], p1_decode_base64);
                index1.push_back(p1_decode);
                baseline_bigsi.insertion(tbl + 1, p1_decode);
            }

            std::vector<bool> Cmp_Array(baseline_bigsi.single_capacity, false);
            Cmp_Array = baseline_bigsi.query(0, tbl + 1);

            for (int i = 0; i < index1.size(); i++)
            {
                int res = 1;
                vector<size_t> check_locations = BF_Hash(index1[i], baseline_bigsi.k, baseline_bigsi.seed, baseline_bigsi.single_capacity);
                for (auto &location : check_locations)
                {
                    res &= Cmp_Array[location];
                }
                if (res)
                {
                    result1[index1[i]] = i;
                }
            }
            for (int j = 0; j < index0.size(); j++)
            {
                if (result1.find(index0[j]) != result1.end())
                    result0[index0[j]] = j;
            }

            unordered_map<string, int> HTE;
            for (auto h1 : result0)
            {
                HTE[h1.first] = h1.second;
            }
            for (auto h2 : result1)
            {
                if (HTE.find(h2.first) != HTE.end())
                {
                    storage2.push_back(pair<int, int>(HTE[h2.first], h2.second));
                }
            }
        }
    }

    if (num == 10)
    {

        int len2 = 0, len3 = 0, len4 = 0, len5 = 0, len6 = 0, len7 = 0, len8 = 0, len9 = 0;

        ocall_read_eneq2(&len2, ein2);
        ocall_read_eneq3(&len3, ein3);
        ocall_read_eneq4(&len4, ein4);
        ocall_read_eneq5(&len5, ein5);
        ocall_read_eneq6(&len6, ein6);
        ocall_read_eneq7(&len7, ein7);
        ocall_read_eneq8(&len8, ein8);
        ocall_read_eneq9(&len9, ein9);

        vector<int> lens = {len1, len2, len3, len4, len5, len6, len7, len8, len9};
        vector<string> ivs = {iv1, iv2, iv3, iv4, iv5, iv6, iv7, iv8, iv9};

        vector<string> index0;

        for (int p0 = 0; p0 < len0; p0++)
        {
            string enindex0 = ein0[p0];
            string p0_decode_base64 = base64_decode(enindex0);
            string p0_decode = aes_256_cbc_decode(cbc_key2, iv0, p0_decode_base64);
            index0.push_back(p0_decode);
            baseline_bigsi.insertion(0, p0_decode);
        }

        for (int tbl = 0; tbl < 9; tbl++)
        {
            vector<string> index1;
            map<string, int> result0;
            map<string, int> result1;

            for (int p1 = 0; p1 < lens[tbl]; p1++)
            {
                string enindex1;
                if (tbl == 0)
                {
                    enindex1 = ein1[p1];
                }
                if (tbl == 1)
                {
                    enindex1 = ein2[p1];
                }
                if (tbl == 2)
                {
                    enindex1 = ein3[p1];
                }
                if (tbl == 3)
                {
                    enindex1 = ein4[p1];
                }
                if (tbl == 4)
                {
                    enindex1 = ein5[p1];
                }
                if (tbl == 5)
                {
                    enindex1 = ein6[p1];
                }
                if (tbl == 6)
                {
                    enindex1 = ein7[p1];
                }
                if (tbl == 7)
                {
                    enindex1 = ein8[p1];
                }
                if (tbl == 8)
                {
                    enindex1 = ein9[p1];
                }

                string p1_decode_base64 = base64_decode(enindex1);
                string p1_decode = aes_256_cbc_decode(cbc_key2, ivs[tbl], p1_decode_base64);
                index1.push_back(p1_decode);
                baseline_bigsi.insertion(tbl + 1, p1_decode);
            }

            std::vector<bool> Cmp_Array(baseline_bigsi.single_capacity, false);
            Cmp_Array = baseline_bigsi.query(0, tbl + 1);

            for (int i = 0; i < index1.size(); i++)
            {
                int res = 1;
                vector<size_t> check_locations = BF_Hash(index1[i], baseline_bigsi.k, baseline_bigsi.seed, baseline_bigsi.single_capacity);
                for (auto &location : check_locations)
                {
                    res &= Cmp_Array[location];
                }
                if (res)
                {
                    result1[index1[i]] = i;
                }
            }
            for (int j = 0; j < index0.size(); j++)
            {
                if (result1.find(index0[j]) != result1.end())
                    result0[index0[j]] = j;
            }

            unordered_map<string, int> HTE;
            for (auto h1 : result0)
            {
                HTE[h1.first] = h1.second;
            }
            for (auto h2 : result1)
            {
                if (HTE.find(h2.first) != HTE.end())
                {
                    storage2.push_back(pair<int, int>(HTE[h2.first], h2.second));
                }
            }
        }
    }

    ocall_close_enquery();
    ocall_close_result();

    e2 = sgx_clock();
}

void ecall_joinsearch1_obl(char **ein0, char **ein1, char **ein2, char **ein3, char **ein4, char **ein5, char **ein6, char **ein7, char **ein8, char **ein9, void *mbdes, char **mbpool)
{
    ocall_open_result();
    ocall_open_enquery();

    clock_t s2, e2;
    clock_t s3, e3;
    clock_t s4, e4;
    clock_t s5, e5;
    clock_t s6, e6;
    clock_t s7, e7;
    clock_t s8, e8;
    clock_t s9, e9;
    clock_t s10, e10;
    clock_t s11, e11;
    clock_t s12, e12;
    clock_t s13, e13;
    clock_t s14, e14;
    clock_t s15, e15;
    clock_t s16, e16;
    clock_t s17, e17;
    clock_t s18, e18;
    clock_t s19, e19;
    clock_t s20, e20;
    s2 = sgx_clock();
    s3 = sgx_clock();

    char *enumber = new char[25];
    ocall_read_s(enumber, 25);
    string senumber = enumber;
    string number_decode_base64 = base64_decode(senumber);
    string sn = aes_256_cbc_decode(cbc_key1, iv0, number_decode_base64);
    int num = atoi(sn.c_str());
    printf("num:%d \n", num);
    liv1++;

    vector<int> table;
    for (int i = 0; i < num; i++)
    {
        char *en = new char[25];
        ocall_read_s(en, 25);
        string sen = en;
        string niv1 = to_string(liv1);
        liv1++;
        string n_decode_base64 = base64_decode(sen);
        string n = aes_256_cbc_decode(cbc_key1, niv1, n_decode_base64);
        table.push_back(atoi(n.c_str()));
    }

    BIGSI baseline_bigsi(num, HASH_NUM, TOTAL_CAP);

    vector<pair<int, int>> storage2;

    int len0 = 0;
    ocall_read_eneq0(&len0, ein0);
    vector<string> index;
    map<string, int> result0;
    map<string, int> result0_2;

    int len1 = 0;
    ocall_read_eneq1(&len1, ein1);
    map<string, int> result1;

    vector<bool> ResultVector_0(len0, false);
    vector<bool> ResultVector_1(len1, false);
    vector<bool> ResultVector_0_2(len0, false);

    vector<string> p_decode_0(len0);
    vector<string> p_decode_1(len1);

    vector<string> IntersectResult_0;
    vector<string> IntersectResult_1;

    int count;

    for (int p = 0; p < len0; p++)
    {
        string enindex = ein0[p];
        string p_decode_base64 = base64_decode(enindex);
        string p_decode = aes_256_cbc_decode(cbc_key2, iv0, p_decode_base64);
        p_decode_0[p] = p_decode;
        baseline_bigsi.insertion(0, p_decode);
    }

    e3 = sgx_clock();
    s7 = sgx_clock();
    if (num == 2)
    {

        vector<string> Result_0;
        vector<string> Result_1;

        printf("len1: %d\n", len1);
        s4 = sgx_clock();
        for (int p = 0; p < len1; p++)
        {
            string enindex = ein1[p];
            string p_decode_base64 = base64_decode(enindex);
            string p_decode = aes_256_cbc_decode(cbc_key2, iv1, p_decode_base64);
            baseline_bigsi.insertion(1, p_decode);

            if (baseline_bigsi.obfmtquery(0, p_decode) == 1)
            {

                Result_1.push_back(p_decode);
                result1[p_decode] = p;
            }
            else
            {
                Result_1.push_back("0");
            }
        }
        e4 = sgx_clock();
        s5 = sgx_clock();
        for (int p = 0; p < len0; p++)
        {
            if (baseline_bigsi.obfmtquery(1, p_decode_0[p]) == 1)
            {
                Result_0.push_back(p_decode_0[p]);
                result0[p_decode_0[p]] = p;
            }
            else
            {
                Result_0.push_back("0");
            }
        }
        e5 = sgx_clock();
        printf("\n0集合元素是否在1中: %f us\n", (double)((e5 - s5)));

        vector<pair<string, int>> F_0;
        count = 0;
        for (int k = 0; k < Result_0.size(); k++)
        {
            if (Result_0[k] != "0")
            {
                F_0.push_back(make_pair(Result_0[k], count));
                count++;
            }
            else
            {
                F_0.push_back(make_pair("000", -1));
            }
        }

        if (count == 0)
        {
            e2 = sgx_clock();
            printf("\nsbf执行时间: %f us\n", (double)((e2 - s2)));
            ocall_close_enquery();
            ocall_close_result();
            return;
        }

        int chunknumber = F_0.size() / (count) + 1;
        vector<vector<pair<string, int>>> Chunks0(chunknumber);

        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_0.size()); j++)
            {
                Chunks0[h].push_back(F_0[h * (count) + j]);
            }

        while (Chunks0.back().size() < count)
        {
            Chunks0.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks0[h], count);
        }

        IntersectResult_0.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                {
                    IntersectResult_0[l] = Chunks0[h][l].first;
                }
            }

        vector<pair<string, int>> F_1;
        count = 0;
        for (int k = 0; k < Result_1.size(); k++)
        {
            if (Result_1[k] != "0")
            {
                F_1.push_back(make_pair(Result_1[k], count));
                count++;
            }
            else
            {
                F_1.push_back(make_pair("000", -1));
            }
        }

        if (count == 0)
        {
            e2 = sgx_clock();
            ocall_close_enquery();
            ocall_close_result();
            return;
        }

        chunknumber = F_1.size() / (count) + 1;

        vector<vector<pair<string, int>>> Chunks1(chunknumber);
        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_1.size()); j++)
            {
                Chunks1[h].push_back(F_1[h * (count) + j]);
            }
        while (Chunks1.back().size() < count)
        {
            Chunks1.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks1[h], count);
        }

        IntersectResult_1.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks1[h][l].first != "000" && IntersectResult_1[l] == "0")
                {
                    IntersectResult_1[l] = Chunks1[h][l].first;
                }
            }

        vector<pair<int, int>> FinalResult(count, make_pair(0, 0));
        int k;

        for (auto fi : IntersectResult_0)
        {
            k = 0;
            if (result0.find(fi) != result0.end())
            {
                for (auto fj : IntersectResult_1)
                {
                    if ((result1.find(fj) != result1.end()) && (fi == fj) && (FinalResult[k] == make_pair(0, 0)))
                    {
                        FinalResult[k] = make_pair(result0[fi], result1[fj]);
                    }
                    k++;
                }
            }
        }
    }

    if (num == 3)
    {
        vector<string> Result_0;
        vector<string> Result_1;
        vector<string> Result_2;

        vector<pair<string, int>> F_0;
        vector<pair<string, int>> F_1;
        vector<pair<string, int>> F_2;

        int len2 = 0;
        ocall_read_eneq2(&len2, ein2);
        map<string, int> result2;
        vector<bool> ResultVector_2(len2, false);
        vector<string> p_decode_2(len2);
        vector<string> IntersectResult_2;
        printf("len2: %d\n", len2);

        for (int p = 0; p < len1; p++)
        {
            string enindex = ein1[p];
            string p_decode_base64 = base64_decode(enindex);
            string p_decode = aes_256_cbc_decode(cbc_key2, iv1, p_decode_base64);
            p_decode_1[p] = p_decode;
            baseline_bigsi.insertion(1, p_decode);
        }

        for (int p = 0; p < len2; p++)
        {
            string enindex = ein2[p];
            string p_decode_base64 = base64_decode(enindex);
            string p_decode = aes_256_cbc_decode(cbc_key2, iv2, p_decode_base64);
            p_decode_2[p] = p_decode;
            baseline_bigsi.insertion(2, p_decode);
        }

        for (int p = 0; p < len1; p++)
        {
            if (baseline_bigsi.obfmtquery(0, p_decode_1[p]) == 1)
            {
                ResultVector_1[p] = 1;
                result1[p_decode_1[p]] = p;
            }
        }

        for (int p = 0; p < len2; p++)
        {
            if (baseline_bigsi.obfmtquery(0, p_decode_2[p]) == 1)
            {
                ResultVector_2[p] = 1;
                result2[p_decode_2[p]] = p;
            }
        }

        int count1 = 0;
        for (int p = 0; p < len0; p++)
        {
            if (baseline_bigsi.obfmtquery(1, p_decode_0[p]) == 1)
            {
                ResultVector_0[p] = 1;
                result0[p_decode_0[p]] = p;
            }
            if (baseline_bigsi.obfmtquery(2, p_decode_0[p]) == 1)
            {
                ResultVector_0_2[p] = 1;
                result0_2[p_decode_0[p]] = p;
            }
            count1++;
        }

        for (int p = 0; p < len0; p++)
        {
            if (ResultVector_0[p])
            {
                Result_0.push_back(p_decode_0[p]);
            }
            else
                Result_0.push_back("0");
        }

        count = 0;
        for (int k = 0; k < Result_0.size(); k++)
        {
            if (Result_0[k] != "0")
            {
                F_0.push_back(make_pair(Result_0[k], count));
                count++;
            }
            else
            {
                F_0.push_back(make_pair("000", -1));
            }
        }
        int chunknumber = F_0.size() / (count) + 1;
        vector<vector<pair<string, int>>> Chunks0(chunknumber);
        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_0.size()); j++)
            {
                Chunks0[h].push_back(F_0[h * (count) + j]);
            }

        while (Chunks0.back().size() < count)
        {
            Chunks0.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks0[h], count);
        }

        IntersectResult_0.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                {
                    IntersectResult_0[l] = Chunks0[h][l].first;
                }
            }

        for (int p = 0; p < len1; p++)
        {
            if (ResultVector_1[p])
                Result_1.push_back(p_decode_1[p]);
            else
                Result_1.push_back("0");
        }

        count = 0;
        for (int k = 0; k < Result_1.size(); k++)
        {
            if (Result_1[k] != "0")
            {
                F_1.push_back(make_pair(Result_1[k], count));
                count++;
            }
            else
            {
                F_1.push_back(make_pair("000", -1));
            }
        }

        chunknumber = F_1.size() / (count) + 1;
        vector<vector<pair<string, int>>> Chunks1(chunknumber);

        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_1.size()); j++)
            {
                Chunks1[h].push_back(F_1[h * (count) + j]);
            }

        while (Chunks1.back().size() < count)
        {
            Chunks1.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks1[h], count);
        }

        IntersectResult_1.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks1[h][l].first != "000" && IntersectResult_1[l] == "0")
                {
                    IntersectResult_1[l] = Chunks1[h][l].first;
                }
            }

        vector<pair<int, int>> FinalResult(count, make_pair(0, 0));

        for (auto fi : IntersectResult_0)
        {
            int k = 0;
            if (result0.find(fi) != result0.end())
            {
                for (auto fj : IntersectResult_1)
                {
                    if ((result1.find(fj) != result1.end()) && (fi == fj) && (FinalResult[k] == make_pair(0, 0)))
                    {
                        FinalResult[k] = make_pair(result0[fi], result1[fj]);
                        ocall_write_result(result1[fj]);
                        ocall_writeendl_result();
                    }
                    k++;
                }
            }
        }

        Result_0.clear();

        int count2 = 0;
        for (int p = 0; p < len0; p++)
        {
            count2++;
            if (ResultVector_0_2[p])
            {
                Result_0.push_back(p_decode_0[p]);
            }
            else
                Result_0.push_back("0");
        }

        count = 0;
        F_0.clear();

        for (int k = 0; k < Result_0.size(); k++)
        {
            if (Result_0[k] != "0")
            {
                F_0.push_back(make_pair(Result_0[k], count));
                count++;
            }
            else
            {
                F_0.push_back(make_pair("000", -1));
            }
        }

        chunknumber = F_0.size() / (count) + 1;
        Chunks0.clear();
        Chunks0 = vector<vector<pair<string, int>>>(chunknumber);

        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_0.size()); j++)
            {
                Chunks0[h].push_back(F_0[h * (count) + j]);
            }

        while (Chunks0.back().size() < count)
        {
            Chunks0.back().push_back(make_pair("000", -1));
        }
        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks0[h], count);
        }

        IntersectResult_0.clear();
        IntersectResult_0.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                {
                    IntersectResult_0[l] = Chunks0[h][l].first;
                }
            }

        for (int p = 0; p < len2; p++)
        {
            if (ResultVector_2[p])
                Result_2.push_back(p_decode_2[p]);
            else
                Result_2.push_back("0");
        }

        count = 0;
        for (int k = 0; k < Result_2.size(); k++)
        {
            if (Result_2[k] != "0")
            {
                F_2.push_back(make_pair(Result_2[k], count));
                count++;
            }
            else
            {
                F_2.push_back(make_pair("000", -1));
            }
        }

        chunknumber = F_2.size() / (count) + 1;
        vector<vector<pair<string, int>>> Chunks2(chunknumber);

        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_2.size()); j++)
            {
                Chunks2[h].push_back(F_2[h * (count) + j]);
            }

        while (Chunks2.back().size() < count)
        {
            Chunks2.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks2[h], count);
        }

        IntersectResult_2.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks2[h][l].first != "000" && IntersectResult_2[l] == "0")
                {
                    IntersectResult_2[l] = Chunks2[h][l].first;
                }
            }

        vector<pair<int, int>> FinalResult1(count, make_pair(0, 0));
        int k;

        for (auto fi : IntersectResult_0)
        {
            k = 0;
            if (result0_2.find(fi) != result0_2.end())
            {
                for (auto fj : IntersectResult_2)
                {
                    if ((result2.find(fj) != result2.end()) && (fi == fj) && (FinalResult1[k] == make_pair(0, 0)))
                    {
                        FinalResult1[k] = make_pair(result0_2[fi], result2[fj]);
                        ocall_write_result(result2[fj]);
                        ocall_writeendl_result();
                    }
                    k++;
                }
            }
        }
    }

    if (num == 5)
    {
        vector<string> Result_0;
        vector<string> Result_1;
        vector<string> Result_2;
        vector<string> Result_3;
        vector<string> Result_4;

        vector<pair<string, int>> F_0;
        vector<pair<string, int>> F_1;
        vector<pair<string, int>> F_2;
        vector<pair<string, int>> F_3;
        vector<pair<string, int>> F_4;

        int len2 = 0, len3 = 0, len4 = 0;
        ocall_read_eneq2(&len2, ein2);
        ocall_read_eneq3(&len3, ein3);
        ocall_read_eneq4(&len4, ein4);
        map<string, int> result2, result3, result4;
        vector<bool> ResultVector_2(len2, false), ResultVector_3(len3, false), ResultVector_4(len4, false);
        vector<string> p_decode_2(len2), p_decode_3(len3), p_decode_4(len4);
        vector<string> IntersectResult_2, IntersectResult_3, IntersectResult_4;

        for (int p = 0; p < len1; p++)
        {
            string enindex = ein1[p];
            string p_decode_base64 = base64_decode(enindex);
            string p_decode = aes_256_cbc_decode(cbc_key2, iv1, p_decode_base64);
            p_decode_1[p] = p_decode;
            baseline_bigsi.insertion(1, p_decode);

            if (baseline_bigsi.obfmtquery(0, p_decode) == 1)
            {
                ResultVector_1[p] = 1;
                result1[p_decode] = p;
            }
        }

        for (int p = 0; p < len0; p++)
        {
            if (baseline_bigsi.obfmtquery(1, p_decode_0[p]) == 1)
            {
                ResultVector_0[p] = 1;
                result0[p_decode_0[p]] = p;
            }
        }

        for (int p = 0; p < len0; p++)
        {
            if (ResultVector_0[p])
            {
                Result_0.push_back(p_decode_0[p]);
            }
            else
            {
                Result_0.push_back("0");
            }
        }

        count = 0;
        for (int k = 0; k < Result_0.size(); k++)
        {
            if (Result_0[k] != "0")
            {
                F_0.push_back(make_pair(Result_0[k], count));
                count++;
            }
            else
            {
                F_0.push_back(make_pair("000", -1));
            }
        }

        int chunknumber = F_0.size() / count + 1;
        vector<vector<pair<string, int>>> Chunks0(chunknumber);
        for (int h = 0; h < chunknumber; h++)
        {
            for (int j = 0; (j < count) && (h * count + j < F_0.size()); j++)
            {
                Chunks0[h].push_back(F_0[h * count + j]);
            }
        }

        while (Chunks0.back().size() < count)
        {
            Chunks0.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks0[h], count);
        }

        IntersectResult_0.resize(count, "0");
        for (int h = 0; h < chunknumber; h++)
        {
            for (int l = 0; l < count; l++)
            {
                if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                {
                    IntersectResult_0[l] = Chunks0[h][l].first;
                }
            }
        }

        for (int p = 0; p < len1; p++)
        {
            if (ResultVector_1[p])
            {
                Result_1.push_back(p_decode_1[p]);
            }
            else
            {
                Result_1.push_back("0");
            }
        }

        count = 0;
        for (int k = 0; k < Result_1.size(); k++)
        {
            if (Result_1[k] != "0")
            {
                F_1.push_back(make_pair(Result_1[k], count));
                count++;
            }
            else
            {
                F_1.push_back(make_pair("000", -1));
            }
        }

        chunknumber = F_1.size() / count + 1;
        vector<vector<pair<string, int>>> Chunks1(chunknumber);
        for (int h = 0; h < chunknumber; h++)
        {
            for (int j = 0; (j < count) && (h * count + j < F_1.size()); j++)
            {
                Chunks1[h].push_back(F_1[h * count + j]);
            }
        }

        while (Chunks1.back().size() < count)
        {
            Chunks1.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks1[h], count);
        }

        IntersectResult_1.resize(count, "0");
        for (int h = 0; h < chunknumber; h++)
        {
            for (int l = 0; l < count; l++)
            {
                if (Chunks1[h][l].first != "000" && IntersectResult_1[l] == "0")
                {
                    IntersectResult_1[l] = Chunks1[h][l].first;
                }
            }
        }

        vector<pair<int, int>> FinalResult(count, make_pair(0, 0));
        for (auto fi : IntersectResult_0)
        {
            int k = 0;
            if (result0.find(fi) != result0.end())
            {
                for (auto fj : IntersectResult_1)
                {
                    if ((result1.find(fj) != result1.end()) && (fi == fj) && (FinalResult[k] == make_pair(0, 0)))
                    {
                        FinalResult[k] = make_pair(result0[fi], result1[fj]);
                        ocall_write_result(result1[fj]);
                        ocall_writeendl_result();
                    }
                    k++;
                }
            }
        }

        vector<vector<string>> Result_x = {Result_2, Result_3, Result_4};
        vector<vector<bool>> ResultVectors = {ResultVector_2, ResultVector_3, ResultVector_4};
        vector<vector<string>> p_decodes = {p_decode_2, p_decode_3, p_decode_4};
        vector<vector<string>> IntersectResults = {IntersectResult_2, IntersectResult_3, IntersectResult_4};
        vector<map<string, int>> results = {result2, result3, result4};
        vector<vector<pair<string, int>>> Fs = {F_2, F_3, F_4};
        vector<int> lens = {len2, len3, len4};
        vector<string> ivs = {iv2, iv3, iv4};

        for (int tbl = 0; tbl < 3; tbl++)
        {
            for (int p = 0; p < lens[tbl]; p++)
            {
                string enindex;
                if (tbl == 0)
                {
                    enindex = ein2[p];
                }
                if (tbl == 1)
                {
                    enindex = ein3[p];
                }
                if (tbl == 2)
                {
                    enindex = ein4[p];
                }
                string p_decode_base64 = base64_decode(enindex);
                string p_decode = aes_256_cbc_decode(cbc_key2, ivs[tbl], p_decode_base64);
                p_decodes[tbl][p] = p_decode;
                baseline_bigsi.insertion(tbl + 2, p_decode);
                if (baseline_bigsi.obfmtquery(0, p_decode) == 1)
                {
                    ResultVectors[tbl][p] = 1;
                    results[tbl][p_decode] = p;
                }
            }

            ResultVector_0.assign(len0, false);
            result0.clear();

            for (int p = 0; p < len0; p++)
            {
                if (baseline_bigsi.obfmtquery(tbl + 2, p_decode_0[p]) == 1)
                {
                    ResultVector_0[p] = 1;
                    result0[p_decode_0[p]] = p;
                }
            }

            Result_0.clear();
            for (int p = 0; p < len0; p++)
            {
                if (ResultVector_0[p])
                {
                    Result_0.push_back(p_decode_0[p]);
                }
                else
                {
                    Result_0.push_back("0");
                }
            }
            count = 0;
            F_0.clear();
            for (int k = 0; k < Result_0.size(); k++)
            {
                if (Result_0[k] != "0")
                {
                    F_0.push_back(make_pair(Result_0[k], count));
                    count++;
                }
                else
                {
                    F_0.push_back(make_pair("000", -1));
                }
            }

            chunknumber = F_0.size() / count + 1;
            Chunks0 = vector<vector<pair<string, int>>>(chunknumber);
            for (int h = 0; h < chunknumber; h++)
            {
                for (int j = 0; (j < count) && (h * count + j < F_0.size()); j++)
                {
                    Chunks0[h].push_back(F_0[h * count + j]);
                }
            }

            while (Chunks0.back().size() < count)
            {
                Chunks0.back().push_back(make_pair("000", -1));
            }

            for (int h = 0; h < chunknumber; h++)
            {
                Oblivious(Chunks0[h], count);
            }

            IntersectResult_0.clear();
            IntersectResult_0.resize(count, "0");

            for (int h = 0; h < chunknumber; h++)
            {
                for (int l = 0; l < count; l++)
                {
                    if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                    {
                        IntersectResult_0[l] = Chunks0[h][l].first;
                    }
                }
            }

            for (int p = 0; p < lens[tbl]; p++)
            {
                if (ResultVectors[tbl][p])
                {
                    Result_x[tbl].push_back(p_decodes[tbl][p]);
                }
                else
                {
                    Result_x[tbl].push_back("0");
                }
            }

            count = 0;

            for (int k = 0; k < Result_x[tbl].size(); k++)
            {
                if (Result_x[tbl][k] != "0")
                {
                    Fs[tbl].push_back(make_pair(Result_x[tbl][k], count));
                    count++;
                }
                else
                {
                    Fs[tbl].push_back(make_pair("000", -1));
                }
            }

            chunknumber = Fs[tbl].size() / count + 1;

            vector<vector<pair<string, int>>> Chunks(chunknumber);
            for (int h = 0; h < chunknumber; h++)
            {
                for (int j = 0; (j < count) && (h * count + j < Fs[tbl].size()); j++)
                {
                    Chunks[h].push_back(Fs[tbl][h * count + j]);
                }
            }

            while (Chunks.back().size() < count)
            {
                Chunks.back().push_back(make_pair("000", -1));
            }

            for (int h = 0; h < chunknumber; h++)
            {
                Oblivious(Chunks[h], count);
            }

            IntersectResults[tbl].resize(count, "0");
            for (int h = 0; h < chunknumber; h++)
            {
                for (int l = 0; l < count; l++)
                {
                    if (Chunks[h][l].first != "000" && IntersectResults[tbl][l] == "0")
                    {
                        IntersectResults[tbl][l] = Chunks[h][l].first;
                    }
                }
            }

            vector<pair<int, int>> FinalResult_temp(count, make_pair(0, 0));

            for (auto fi : IntersectResult_0)
            {
                int k = 0;
                if (result0.find(fi) != result0.end())
                {
                    for (auto fj : IntersectResults[tbl])
                    {
                        if ((results[tbl].find(fj) != results[tbl].end()) && (fi == fj) && (FinalResult_temp[k] == make_pair(0, 0)))
                        {
                            FinalResult_temp[k] = make_pair(result0[fi], results[tbl][fj]);
                            ocall_write_result(results[tbl][fj]);
                            ocall_writeendl_result();
                        }
                        k++;
                    }
                }
            }
        }
    }

    if (num == 10)
    {
        vector<string> Result_0, Result_1, Result_2, Result_3, Result_4, Result_5, Result_6, Result_7, Result_8, Result_9;
        vector<pair<string, int>> F_0, F_1, F_2, F_3, F_4, F_5, F_6, F_7, F_8, F_9;
        vector<string> IntersectResult_2, IntersectResult_3, IntersectResult_4, IntersectResult_5, IntersectResult_6, IntersectResult_7, IntersectResult_8, IntersectResult_9;

        int len1 = 0, len2 = 0, len3 = 0, len4 = 0, len5 = 0, len6 = 0, len7 = 0, len8 = 0, len9 = 0;
        ocall_read_eneq1(&len1, ein1);
        ocall_read_eneq2(&len2, ein2);
        ocall_read_eneq3(&len3, ein3);
        ocall_read_eneq4(&len4, ein4);
        ocall_read_eneq5(&len5, ein5);
        ocall_read_eneq6(&len6, ein6);
        ocall_read_eneq7(&len7, ein7);
        ocall_read_eneq8(&len8, ein8);
        ocall_read_eneq9(&len9, ein9);

        map<string, int> result1, result2, result3, result4, result5, result6, result7, result8, result9;
        vector<bool> ResultVector_1(len1, false), ResultVector_2(len2, false), ResultVector_3(len3, false), ResultVector_4(len4, false),
            ResultVector_5(len5, false), ResultVector_6(len6, false), ResultVector_7(len7, false), ResultVector_8(len8, false),
            ResultVector_9(len9, false);
        vector<string> p_decode_1(len1), p_decode_2(len2), p_decode_3(len3), p_decode_4(len4), p_decode_5(len5), p_decode_6(len6),
            p_decode_7(len7), p_decode_8(len8), p_decode_9(len9);
        vector<string> IntersectResult_0;

        for (int p = 0; p < len1; p++)
        {
            string enindex = ein1[p];
            string p_decode_base64 = base64_decode(enindex);
            string p_decode = aes_256_cbc_decode(cbc_key2, iv1, p_decode_base64);
            p_decode_1[p] = p_decode;
            baseline_bigsi.insertion(1, p_decode);

            if (baseline_bigsi.obfmtquery(0, p_decode) == 1)
            {
                ResultVector_1[p] = 1;
                result1[p_decode] = p;
            }
        }

        for (int p = 0; p < len0; p++)
        {
            if (baseline_bigsi.obfmtquery(1, p_decode_0[p]) == 1)
            {
                ResultVector_0[p] = 1;
                result0[p_decode_0[p]] = p;
            }
        }

        for (int p = 0; p < len0; p++)
        {
            if (ResultVector_0[p])
            {
                Result_0.push_back(p_decode_0[p]);
            }
            else
            {
                Result_0.push_back("0");
            }
        }

        int count = 0;
        for (int k = 0; k < Result_0.size(); k++)
        {
            if (Result_0[k] != "0")
            {
                F_0.push_back(make_pair(Result_0[k], count));
                count++;
            }
            else
            {
                F_0.push_back(make_pair("000", -1));
            }
        }

        int chunknumber = F_0.size() / count + 1;
        vector<vector<pair<string, int>>> Chunks0(chunknumber);
        for (int h = 0; h < chunknumber; h++)
        {
            for (int j = 0; (j < count) && (h * count + j < F_0.size()); j++)
            {
                Chunks0[h].push_back(F_0[h * count + j]);
            }
        }

        while (Chunks0.back().size() < count)
        {
            Chunks0.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks0[h], count);
        }

        IntersectResult_0.resize(count, "0");
        for (int h = 0; h < chunknumber; h++)
        {
            for (int l = 0; l < count; l++)
            {
                if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                {
                    IntersectResult_0[l] = Chunks0[h][l].first;
                }
            }
        }

        for (int p = 0; p < len1; p++)
        {
            if (ResultVector_1[p])
            {
                Result_1.push_back(p_decode_1[p]);
            }
            else
            {
                Result_1.push_back("0");
            }
        }

        count = 0;
        for (int k = 0; k < Result_1.size(); k++)
        {
            if (Result_1[k] != "0")
            {
                F_1.push_back(make_pair(Result_1[k], count));
                count++;
            }
            else
            {
                F_1.push_back(make_pair("000", -1));
            }
        }

        chunknumber = F_1.size() / count + 1;
        vector<vector<pair<string, int>>> Chunks1(chunknumber);
        for (int h = 0; h < chunknumber; h++)
        {
            for (int j = 0; (j < count) && (h * count + j < F_1.size()); j++)
            {
                Chunks1[h].push_back(F_1[h * count + j]);
            }
        }

        while (Chunks1.back().size() < count)
        {
            Chunks1.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks1[h], count);
        }

        IntersectResult_1.resize(count, "0");
        for (int h = 0; h < chunknumber; h++)
        {
            for (int l = 0; l < count; l++)
            {
                if (Chunks1[h][l].first != "000" && IntersectResult_1[l] == "0")
                {
                    IntersectResult_1[l] = Chunks1[h][l].first;
                }
            }
        }

        vector<pair<int, int>> FinalResult(count, make_pair(0, 0));
        for (auto fi : IntersectResult_0)
        {
            int k = 0;
            if (result0.find(fi) != result0.end())
            {
                for (auto fj : IntersectResult_1)
                {
                    if ((result1.find(fj) != result1.end()) && (fi == fj) && (FinalResult[k] == make_pair(0, 0)))
                    {
                        FinalResult[k] = make_pair(result0[fi], result1[fj]);
                        ocall_write_result(result1[fj]);
                        ocall_writeendl_result();
                    }
                    k++;
                }
            }
        }

        vector<vector<string>> Results = {Result_2, Result_3, Result_4, Result_5, Result_6, Result_7, Result_8, Result_9};
        vector<vector<bool>> ResultVectors = {ResultVector_2, ResultVector_3, ResultVector_4, ResultVector_5, ResultVector_6, ResultVector_7, ResultVector_8, ResultVector_9};
        vector<vector<string>> p_decodes = {p_decode_2, p_decode_3, p_decode_4, p_decode_5, p_decode_6, p_decode_7, p_decode_8, p_decode_9};
        vector<map<string, int>> results = {result2, result3, result4, result5, result6, result7, result8, result9};
        vector<vector<pair<string, int>>> Fs = {F_2, F_3, F_4, F_5, F_6, F_7, F_8, F_9};
        vector<int> lens = {len2, len3, len4, len5, len6, len7, len8, len9};
        vector<string> ivs = {iv2, iv3, iv4, iv5, iv6, iv7, iv8, iv9};
        vector<vector<string>> IntersectResults = {
            IntersectResult_2, IntersectResult_3, IntersectResult_4,
            IntersectResult_5, IntersectResult_6, IntersectResult_7,
            IntersectResult_8, IntersectResult_9};

        for (int tbl = 0; tbl < 8; tbl++)
        {
            for (int p = 0; p < lens[tbl]; p++)
            {
                string enindex;
                if (tbl == 0)
                {
                    enindex = ein2[p];
                }
                if (tbl == 1)
                {
                    enindex = ein3[p];
                }
                if (tbl == 2)
                {
                    enindex = ein4[p];
                }
                if (tbl == 3)
                {
                    enindex = ein5[p];
                }
                if (tbl == 4)
                {
                    enindex = ein6[p];
                }
                if (tbl == 5)
                {
                    enindex = ein7[p];
                }
                if (tbl == 6)
                {
                    enindex = ein8[p];
                }
                if (tbl == 7)
                {
                    enindex = ein9[p];
                }

                string p_decode_base64 = base64_decode(enindex);
                string p_decode = aes_256_cbc_decode(cbc_key2, ivs[tbl], p_decode_base64);
                p_decodes[tbl][p] = p_decode;
                baseline_bigsi.insertion(tbl + 2, p_decode);

                if (baseline_bigsi.obfmtquery(0, p_decode) == 1)
                {
                    ResultVectors[tbl][p] = 1;
                    results[tbl][p_decode] = p;
                }
            }

            ResultVector_0.assign(len0, false);
            result0.clear();

            for (int p = 0; p < len0; p++)
            {
                if (baseline_bigsi.obfmtquery(tbl + 2, p_decode_0[p]) == 1)
                {
                    ResultVector_0[p] = 1;
                    result0[p_decode_0[p]] = p;
                }
            }

            Result_0.clear();
            for (int p = 0; p < len0; p++)
            {
                if (ResultVector_0[p])
                {
                    Result_0.push_back(p_decode_0[p]);
                }
                else
                {
                    Result_0.push_back("0");
                }
            }

            count = 0;
            F_0.clear();
            for (int k = 0; k < Result_0.size(); k++)
            {
                if (Result_0[k] != "0")
                {
                    F_0.push_back(make_pair(Result_0[k], count));
                    count++;
                }
                else
                {
                    F_0.push_back(make_pair("000", -1));
                }
            }

            chunknumber = F_0.size() / count + 1;
            Chunks0 = vector<vector<pair<string, int>>>(chunknumber);

            for (int h = 0; h < chunknumber; h++)
            {
                for (int j = 0; (j < count) && (h * count + j < F_0.size()); j++)
                {
                    Chunks0[h].push_back(F_0[h * count + j]);
                }
            }

            while (Chunks0.back().size() < count)
            {
                Chunks0.back().push_back(make_pair("000", -1));
            }

            for (int h = 0; h < chunknumber; h++)
            {
                Oblivious(Chunks0[h], count);
            }

            IntersectResult_0.clear();
            IntersectResult_0.resize(count, "0");

            for (int h = 0; h < chunknumber; h++)
            {
                for (int l = 0; l < count; l++)
                {
                    if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                    {
                        IntersectResult_0[l] = Chunks0[h][l].first;
                    }
                }
            }

            for (int p = 0; p < lens[tbl]; p++)
            {
                if (ResultVectors[tbl][p])
                {
                    Results[tbl].push_back(p_decodes[tbl][p]);
                }
                else
                {
                    Results[tbl].push_back("0");
                }
            }

            count = 0;

            for (int k = 0; k < Results[tbl].size(); k++)
            {
                if (Results[tbl][k] != "0")
                {
                    Fs[tbl].push_back(make_pair(Results[tbl][k], count));
                    count++;
                }
                else
                {
                    Fs[tbl].push_back(make_pair("000", -1));
                }
            }

            chunknumber = Fs[tbl].size() / count + 1;

            vector<vector<pair<string, int>>> Chunks(chunknumber);

            for (int h = 0; h < chunknumber; h++)
            {
                for (int j = 0; (j < count) && (h * count + j < Fs[tbl].size()); j++)
                {
                    Chunks[h].push_back(Fs[tbl][h * count + j]);
                }
            }

            while (Chunks.back().size() < count)
            {
                Chunks.back().push_back(make_pair("000", -1));
            }

            for (int h = 0; h < chunknumber; h++)
            {
                Oblivious(Chunks[h], count);
            }

            IntersectResults[tbl].resize(count, "0");

            for (int h = 0; h < chunknumber; h++)
            {
                for (int l = 0; l < count; l++)
                {
                    if (Chunks[h][l].first != "000" && IntersectResults[tbl][l] == "0")
                    {
                        IntersectResults[tbl][l] = Chunks[h][l].first;
                    }
                }
            }
            int count1 = 0;
            vector<pair<int, int>> FinalResult_temp(count, make_pair(0, 0));
            for (auto fi : IntersectResult_0)
            {
                int k = 0;
                if (result0.find(fi) != result0.end())
                {
                    for (auto fj : IntersectResults[tbl])
                    {
                        if ((results[tbl].find(fj) != results[tbl].end()) && (fi == fj) && (FinalResult_temp[k] == make_pair(0, 0)))
                        {
                            FinalResult_temp[k] = make_pair(result0[fi], results[tbl][fj]);
                            ocall_write_result(results[tbl][fj]);
                            ocall_writeendl_result();
                            count1++;
                        }
                        k++;
                    }
                }
            }
            printf("The value of count1 is: %d\n", count1);
        }
    }

    e2 = sgx_clock();
    e7 = sgx_clock();
    printf("\ntra(obli)执行时间: %f us\n", (double)((e2 - s2)));
    ocall_close_enquery();
    ocall_close_result();
}

void ecall_joinsearch2(char **ein0, char **ein1, char **ein2, char **ein3, char **ein4, char **ein5, char **ein6, char **ein7, char **ein8, char **ein9, void *mbdes, char **mbpool)
{
    ocall_open_result();
    ocall_open_enquery();

    clock_t s2, e2;
    s2 = sgx_clock();

    char *enumber = new char[25];
    ocall_read_s(enumber, 25);
    string senumber = enumber;
    string number_decode_base64 = base64_decode(senumber);
    string sn = aes_256_cbc_decode(cbc_key1, iv0, number_decode_base64);
    int num = atoi(sn.c_str());
    printf("num:%d \n", num);
    liv1++;

    vector<int> table;
    for (int i = 0; i < num; i++)
    {
        char *en = new char[25];
        ocall_read_s(en, 25);
        string sen = en;
        string niv1 = to_string(liv1);
        liv1++;
        string n_decode_base64 = base64_decode(sen);
        string n = aes_256_cbc_decode(cbc_key1, niv1, n_decode_base64);
        table.push_back(atoi(n.c_str()));
    }

    CSCBF cscbf(REP_TIME, PART_NUM, TOTAL_CAP, HASH_NUM, num);
    vector<pair<int, int>> storage2;

    int len0 = 0;
    ocall_read_eneq0(&len0, ein0);
    vector<string> index;

    int len1 = 0;
    ocall_read_eneq1(&len1, ein1);

    map<string, int> result2;
    map<string, int> result3;
    map<string, int> result4;
    map<string, int> result5;
    map<string, int> result6;
    map<string, int> result7;
    map<string, int> result8;
    map<string, int> result9;

    vector<string> ivs = {iv2, iv3, iv4, iv5, iv6, iv7, iv8, iv9};

    for (int p = 0; p < len0; p++)
    {
        string enindex = ein0[p];
        string p_decode_base64 = base64_decode(enindex);
        string p_decode = aes_256_cbc_decode(cbc_key2, iv0, p_decode_base64);
        index.push_back(p_decode);
        cscbf.insertion(to_string(0), p_decode);
    }

    if (num == 2)
    {
        map<string, int> result0;
        map<string, int> result1;
        for (int p = 0; p < len1; p++)
        {
            string enindex = ein1[p];
            string p_decode_base64 = base64_decode(enindex);
            string p_decode = aes_256_cbc_decode(cbc_key2, iv1, p_decode_base64);
            cscbf.insertion(to_string(1), p_decode);

            int res = 1;
            for (int set_ID = 1; set_ID < num; set_ID++)
            {
                int cscbf_res = cscbf.query(set_ID, p_decode);
                res &= cscbf_res;
                if (!res)
                {
                    break;
                }
            }
            if (res)
            {
                result1[p_decode] = p;
            }
        }
        for (int j = 0; j < index.size(); j++)
        {
            if (result1.find(index[j]) != result1.end())
                result0[index[j]] = j;
        }

        unordered_map<string, int> HTE;
        for (auto h1 : result0)
        {
            HTE[h1.first] = h1.second;
        }
        for (auto h2 : result1)
        {
            if (HTE.find(h2.first) != HTE.end())
            {
                storage2.push_back(pair<int, int>(HTE[h2.first], h2.second));
            }
        }
    }

    if (num == 3)
    {

        int len1 = 0, len2 = 0;

        ocall_read_eneq1(&len1, ein1);
        ocall_read_eneq2(&len2, ein2);
        vector<int> lens = {len1, len2};
        vector<string> ivs = {iv1, iv2};

        for (int tbl = 0; tbl < 2; tbl++)
        {
            map<string, int> result0;
            map<string, int> result1;
            for (int p = 0; p < lens[tbl]; p++)
            {
                string enindex;
                if (tbl == 0)
                {
                    enindex = ein1[p];
                }
                if (tbl == 1)
                {
                    enindex = ein2[p];
                }

                string p_decode_base64 = base64_decode(enindex);
                string p_decode = aes_256_cbc_decode(cbc_key2, ivs[tbl], p_decode_base64);
                cscbf.insertion(to_string(tbl + 1), p_decode);

                int res = 1;
                for (int set_ID = 1; set_ID < 2; set_ID++)
                {

                    int cscbf_res = cscbf.query(tbl + 1, p_decode);
                    res &= cscbf_res;
                    if (!res)
                    {
                        break;
                    }
                }
                if (res)
                {
                    result1[p_decode] = p;
                }
            }
            for (int j = 0; j < index.size(); j++)
            {
                if (result1.find(index[j]) != result1.end())
                    result0[index[j]] = j;
            }

            unordered_map<string, int> HTE;
            for (auto h1 : result0)
            {
                HTE[h1.first] = h1.second;
            }
            for (auto h2 : result1)
            {
                if (HTE.find(h2.first) != HTE.end())
                {
                    storage2.push_back(pair<int, int>(HTE[h2.first], h2.second));
                }
            }
        }
    }

    if (num == 5)
    {

        int len1 = 0, len2 = 0, len3 = 0, len4 = 0;

        ocall_read_eneq1(&len1, ein1);
        ocall_read_eneq2(&len2, ein2);
        ocall_read_eneq3(&len3, ein3);
        ocall_read_eneq4(&len4, ein4);
        vector<int> lens = {len1, len2, len3, len4};
        vector<string> ivs = {iv1, iv2, iv3, iv4};

        for (int tbl = 0; tbl < 4; tbl++)
        {
            map<string, int> result0;
            map<string, int> result1;
            for (int p = 0; p < lens[tbl]; p++)
            {
                string enindex;
                if (tbl == 0)
                {
                    enindex = ein1[p];
                }
                if (tbl == 1)
                {
                    enindex = ein2[p];
                }

                if (tbl == 2)
                {
                    enindex = ein3[p];
                }
                if (tbl == 3)
                {
                    enindex = ein4[p];
                }

                string p_decode_base64 = base64_decode(enindex);
                string p_decode = aes_256_cbc_decode(cbc_key2, ivs[tbl], p_decode_base64);
                cscbf.insertion(to_string(tbl + 1), p_decode);

                int res = 1;
                for (int set_ID = 1; set_ID < 2; set_ID++)
                {

                    int cscbf_res = cscbf.query(tbl + 1, p_decode);
                    res &= cscbf_res;
                    if (!res)
                    {
                        break;
                    }
                }
                if (res)
                {
                    result1[p_decode] = p;
                }
            }
            for (int j = 0; j < index.size(); j++)
            {
                if (result1.find(index[j]) != result1.end())
                    result0[index[j]] = j;
            }

            unordered_map<string, int> HTE;
            for (auto h1 : result0)
            {
                HTE[h1.first] = h1.second;
            }
            for (auto h2 : result1)
            {
                if (HTE.find(h2.first) != HTE.end())
                {
                    storage2.push_back(pair<int, int>(HTE[h2.first], h2.second));
                }
            }
        }
    }

    if (num == 10)
    {

        int len1 = 0, len2 = 0, len3 = 0, len4 = 0, len5 = 0, len6 = 0, len7 = 0, len8 = 0, len9 = 0;

        ocall_read_eneq1(&len1, ein1);
        ocall_read_eneq2(&len2, ein2);
        ocall_read_eneq3(&len3, ein3);
        ocall_read_eneq4(&len4, ein4);
        ocall_read_eneq5(&len5, ein5);
        ocall_read_eneq6(&len6, ein6);
        ocall_read_eneq7(&len7, ein7);
        ocall_read_eneq8(&len8, ein8);
        ocall_read_eneq9(&len9, ein9);

        vector<int> lens = {len1, len2, len3, len4, len5, len6, len7, len8, len9};
        vector<string> ivs = {iv1, iv2, iv3, iv4, iv5, iv6, iv7, iv8, iv9};

        for (int tbl = 0; tbl < 9; tbl++)
        {
            map<string, int> result0;
            map<string, int> result1;
            for (int p = 0; p < lens[tbl]; p++)
            {
                string enindex;
                if (tbl == 0)
                {
                    enindex = ein1[p];
                }
                if (tbl == 1)
                {
                    enindex = ein2[p];
                }
                if (tbl == 2)
                {
                    enindex = ein3[p];
                }
                if (tbl == 3)
                {
                    enindex = ein4[p];
                }
                if (tbl == 4)
                {
                    enindex = ein5[p];
                }
                if (tbl == 5)
                {
                    enindex = ein6[p];
                }
                if (tbl == 6)
                {
                    enindex = ein7[p];
                }
                if (tbl == 7)
                {
                    enindex = ein8[p];
                }
                if (tbl == 8)
                {
                    enindex = ein9[p];
                }

                string p_decode_base64 = base64_decode(enindex);
                string p_decode = aes_256_cbc_decode(cbc_key2, ivs[tbl], p_decode_base64);
                cscbf.insertion(to_string(tbl + 1), p_decode);

                int res = 1;
                for (int set_ID = 1; set_ID < 2; set_ID++)
                {

                    int cscbf_res = cscbf.query(tbl + 1, p_decode);
                    res &= cscbf_res;
                    if (!res)
                    {
                        break;
                    }
                }
                if (res)
                {
                    result1[p_decode] = p;
                }
            }
            for (int j = 0; j < index.size(); j++)
            {
                if (result1.find(index[j]) != result1.end())
                    result0[index[j]] = j;
            }

            unordered_map<string, int> HTE;
            for (auto h1 : result0)
            {
                HTE[h1.first] = h1.second;
            }
            for (auto h2 : result1)
            {
                if (HTE.find(h2.first) != HTE.end())
                {
                    storage2.push_back(pair<int, int>(HTE[h2.first], h2.second));
                }
            }
        }
    }

    e2 = sgx_clock();
    printf("\nsbf执行时间: %f us\n", (double)((e2 - s2)));

    ocall_close_enquery();
    ocall_close_result();
}

void ecall_joinsearch2_obl(char **ein0, char **ein1, char **ein2, char **ein3, char **ein4, char **ein5, char **ein6, char **ein7, char **ein8, char **ein9, void *mbdes, char **mbpool)
{
    ocall_open_result();
    ocall_open_enquery();

    clock_t s2, e2;
    s2 = sgx_clock();

    char *enumber = new char[25];
    ocall_read_s(enumber, 25);
    string senumber = enumber;
    string number_decode_base64 = base64_decode(senumber);
    string sn = aes_256_cbc_decode(cbc_key1, iv0, number_decode_base64);
    int num = atoi(sn.c_str());
    printf("num:%d \n", num);
    liv1++;

    vector<int> table;
    for (int i = 0; i < num; i++)
    {
        char *en = new char[25];
        ocall_read_s(en, 25);
        string sen = en;
        string niv1 = to_string(liv1);
        liv1++;
        string n_decode_base64 = base64_decode(sen);
        string n = aes_256_cbc_decode(cbc_key1, niv1, n_decode_base64);
        table.push_back(atoi(n.c_str()));
    }

    CSCBF cscbf(REP_TIME, PART_NUM, TOTAL_CAP, HASH_NUM, num);
    vector<pair<int, int>> storage2;

    int len0 = 0;
    ocall_read_eneq0(&len0, ein0);
    vector<string> index;
    map<string, int> result0;
    map<string, int> result0_2;

    int len1 = 0;
    ocall_read_eneq1(&len1, ein1);
    map<string, int> result1;

    vector<bool> ResultVector_0(len0, false);
    vector<bool> ResultVector_1(len1, false);
    vector<bool> ResultVector_0_2(len0, false);

    vector<string> p_decode_0(len0);
    vector<string> p_decode_1(len1);

    vector<string> IntersectResult_0;
    vector<string> IntersectResult_1;

    int count;

    for (int p = 0; p < len0; p++)
    {
        string enindex = ein0[p];
        string p_decode_base64 = base64_decode(enindex);
        string p_decode = aes_256_cbc_decode(cbc_key2, iv0, p_decode_base64);
        p_decode_0[p] = p_decode;
        cscbf.insertion(to_string(0), p_decode);
    }
    printf("len0: %d\n", len0);

    if (num == 2)
    {

        vector<string> Result_0;
        vector<string> Result_1;

        printf("len1: %d\n", len1);
        for (int p = 0; p < len1; p++)
        {
            string enindex = ein1[p];
            string p_decode_base64 = base64_decode(enindex);
            string p_decode = aes_256_cbc_decode(cbc_key2, iv1, p_decode_base64);
            cscbf.insertion(to_string(1), p_decode);

            if (cscbf.obfquery(0, p_decode) == 1)
            {
                Result_1.push_back(p_decode);
                result1[p_decode] = p;
            }
            else
            {
                Result_1.push_back("0");
            }
        }

        for (int p = 0; p < len0; p++)
        {
            if (cscbf.obfquery(1, p_decode_0[p]) == 1)
            {
                Result_0.push_back(p_decode_0[p]);
                result0[p_decode_0[p]] = p;
            }
            else
            {
                Result_0.push_back("0");
            }
        }

        vector<pair<string, int>> F_0;
        count = 0;
        for (int k = 0; k < Result_0.size(); k++)
        {
            if (Result_0[k] != "0")
            {
                F_0.push_back(make_pair(Result_0[k], count));
                count++;
            }
            else
            {
                F_0.push_back(make_pair("000", -1));
            }
        }

        if (count == 0)
        {
            e2 = sgx_clock();
            printf("\nsbf执行时间: %f us\n", (double)((e2 - s2)));
            ocall_close_enquery();
            ocall_close_result();
            return;
        }

        int chunknumber = F_0.size() / (count) + 1;
        vector<vector<pair<string, int>>> Chunks0(chunknumber);

        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_0.size()); j++)
            {
                Chunks0[h].push_back(F_0[h * (count) + j]);
            }

        while (Chunks0.back().size() < count)
        {
            Chunks0.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks0[h], count);
        }

        IntersectResult_0.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                {
                    IntersectResult_0[l] = Chunks0[h][l].first;
                }
            }

        vector<pair<string, int>> F_1;
        count = 0;
        for (int k = 0; k < Result_1.size(); k++)
        {
            if (Result_1[k] != "0")
            {
                F_1.push_back(make_pair(Result_1[k], count));
                count++;
            }
            else
            {
                F_1.push_back(make_pair("000", -1));
            }
        }

        if (count == 0)
        {
            e2 = sgx_clock();
            printf("\nsbf执行时间: %f us\n", (double)((e2 - s2)));
            ocall_close_enquery();
            ocall_close_result();
            return;
        }

        chunknumber = F_1.size() / (count) + 1;
        vector<vector<pair<string, int>>> Chunks1(chunknumber);

        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_1.size()); j++)
            {
                Chunks1[h].push_back(F_1[h * (count) + j]);
            }

        while (Chunks1.back().size() < count)
        {
            Chunks1.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks1[h], count);
        }

        IntersectResult_1.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks1[h][l].first != "000" && IntersectResult_1[l] == "0")
                {
                    IntersectResult_1[l] = Chunks1[h][l].first;
                }
            }

        vector<pair<int, int>> FinalResult(count, make_pair(0, 0));
        int k;

        for (auto fi : IntersectResult_0)
        {
            k = 0;
            if (result0.find(fi) != result0.end())
            {
                for (auto fj : IntersectResult_1)
                {
                    if ((result1.find(fj) != result1.end()) && (fi == fj) && (FinalResult[k] == make_pair(0, 0)))
                    {
                        FinalResult[k] = make_pair(result0[fi], result1[fj]);
                    }
                    k++;
                }
            }
        }
    }

    if (num == 3)
    {
        vector<string> Result_0;
        vector<string> Result_1;
        vector<string> Result_2;

        vector<pair<string, int>> F_0;
        vector<pair<string, int>> F_1;
        vector<pair<string, int>> F_2;

        int len2 = 0;
        ocall_read_eneq2(&len2, ein2);
        map<string, int> result2;
        vector<bool> ResultVector_2(len2, false);
        vector<string> p_decode_2(len2);
        vector<string> IntersectResult_2;
        printf("len2: %d\n", len2);

        for (int p = 0; p < len1; p++)
        {
            string enindex = ein1[p];
            string p_decode_base64 = base64_decode(enindex);
            string p_decode = aes_256_cbc_decode(cbc_key2, iv1, p_decode_base64);
            p_decode_1[p] = p_decode;
            cscbf.insertion(to_string(1), p_decode);
        }

        for (int p = 0; p < len2; p++)
        {
            string enindex = ein2[p];
            string p_decode_base64 = base64_decode(enindex);
            string p_decode = aes_256_cbc_decode(cbc_key2, iv2, p_decode_base64);
            p_decode_2[p] = p_decode;
            cscbf.insertion(to_string(2), p_decode);
        }

        for (int p = 0; p < len1; p++)
        {
            if (cscbf.obfquery(0, p_decode_1[p]) == 1)
            {
                ResultVector_1[p] = 1;
                result1[p_decode_1[p]] = p;
            }
        }

        for (int p = 0; p < len2; p++)
        {
            if (cscbf.obfquery(0, p_decode_2[p]) == 1)
            {
                ResultVector_2[p] = 1;
                result2[p_decode_2[p]] = p;
            }
        }

        int count1 = 0;
        for (int p = 0; p < len0; p++)
        {
            if (cscbf.obfquery(1, p_decode_0[p]) == 1)
            {
                ResultVector_0[p] = 1;
                result0[p_decode_0[p]] = p;
            }
            if (cscbf.obfquery(2, p_decode_0[p]) == 1)
            {
                ResultVector_0_2[p] = 1;
                result0_2[p_decode_0[p]] = p;
            }
            count1++;
        }

        for (int p = 0; p < len0; p++)
        {
            if (ResultVector_0[p])
            {
                Result_0.push_back(p_decode_0[p]);
            }
            else
                Result_0.push_back("0");
        }

        count = 0;
        for (int k = 0; k < Result_0.size(); k++)
        {
            if (Result_0[k] != "0")
            {
                F_0.push_back(make_pair(Result_0[k], count));
                count++;
            }
            else
            {
                F_0.push_back(make_pair("000", -1));
            }
        }
        int chunknumber = F_0.size() / (count) + 1;
        vector<vector<pair<string, int>>> Chunks0(chunknumber);
        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_0.size()); j++)
            {
                Chunks0[h].push_back(F_0[h * (count) + j]);
            }

        while (Chunks0.back().size() < count)
        {
            Chunks0.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks0[h], count);
        }

        IntersectResult_0.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                {
                    IntersectResult_0[l] = Chunks0[h][l].first;
                }
            }

        for (int p = 0; p < len1; p++)
        {
            if (ResultVector_1[p])
                Result_1.push_back(p_decode_1[p]);
            else
                Result_1.push_back("0");
        }

        count = 0;
        for (int k = 0; k < Result_1.size(); k++)
        {
            if (Result_1[k] != "0")
            {
                F_1.push_back(make_pair(Result_1[k], count));
                count++;
            }
            else
            {
                F_1.push_back(make_pair("000", -1));
            }
        }

        chunknumber = F_1.size() / (count) + 1;
        vector<vector<pair<string, int>>> Chunks1(chunknumber);

        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_1.size()); j++)
            {
                Chunks1[h].push_back(F_1[h * (count) + j]);
            }

        while (Chunks1.back().size() < count)
        {
            Chunks1.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks1[h], count);
        }

        IntersectResult_1.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks1[h][l].first != "000" && IntersectResult_1[l] == "0")
                {
                    IntersectResult_1[l] = Chunks1[h][l].first;
                }
            }

        vector<pair<int, int>> FinalResult(count, make_pair(0, 0));

        for (auto fi : IntersectResult_0)
        {
            int k = 0;
            if (result0.find(fi) != result0.end())
            {
                for (auto fj : IntersectResult_1)
                {
                    if ((result1.find(fj) != result1.end()) && (fi == fj) && (FinalResult[k] == make_pair(0, 0)))
                    {
                        FinalResult[k] = make_pair(result0[fi], result1[fj]);
                    }
                    k++;
                }
            }
        }

        Result_0.clear();

        int count2 = 0;
        for (int p = 0; p < len0; p++)
        {
            count2++;
            if (ResultVector_0_2[p])
            {
                Result_0.push_back(p_decode_0[p]);
            }
            else
                Result_0.push_back("0");
        }

        count = 0;
        F_0.clear();

        for (int k = 0; k < Result_0.size(); k++)
        {
            if (Result_0[k] != "0")
            {
                F_0.push_back(make_pair(Result_0[k], count));
                count++;
            }
            else
            {
                F_0.push_back(make_pair("000", -1));
            }
        }

        //     printf("(%s, %d) ", elem.first.c_str(), elem.second);

        chunknumber = F_0.size() / (count) + 1;
        Chunks0.clear();
        Chunks0 = vector<vector<pair<string, int>>>(chunknumber);

        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_0.size()); j++)
            {
                Chunks0[h].push_back(F_0[h * (count) + j]);
            }

        while (Chunks0.back().size() < count)
        {
            Chunks0.back().push_back(make_pair("000", -1));
        }

        //         printf("(%s, %d) ", elem.first.c_str(), elem.second);

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks0[h], count);
        }

        IntersectResult_0.clear();
        IntersectResult_0.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                {
                    IntersectResult_0[l] = Chunks0[h][l].first;
                }
            }

        for (int p = 0; p < len2; p++)
        {
            if (ResultVector_2[p])
                Result_2.push_back(p_decode_2[p]);
            else
                Result_2.push_back("0");
        }

        count = 0;
        for (int k = 0; k < Result_2.size(); k++)
        {
            if (Result_2[k] != "0")
            {
                F_2.push_back(make_pair(Result_2[k], count));
                count++;
            }
            else
            {
                F_2.push_back(make_pair("000", -1));
            }
        }

        chunknumber = F_2.size() / (count) + 1;
        vector<vector<pair<string, int>>> Chunks2(chunknumber);

        for (int h = 0; h < chunknumber; h++)
            for (int j = 0; (j < count) && (h * (count) + j < F_2.size()); j++)
            {
                Chunks2[h].push_back(F_2[h * (count) + j]);
            }

        while (Chunks2.back().size() < count)
        {
            Chunks2.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks2[h], count);
        }

        IntersectResult_2.resize(count, "0");

        for (int h = 0; h < chunknumber; h++)
            for (int l = 0; l < count; l++)
            {
                if (Chunks2[h][l].first != "000" && IntersectResult_2[l] == "0")
                {
                    IntersectResult_2[l] = Chunks2[h][l].first;
                }
            }

        vector<pair<int, int>> FinalResult1(count, make_pair(0, 0));
        int k;

        for (auto fi : IntersectResult_0)
        {
            k = 0;
            if (result0_2.find(fi) != result0_2.end())
            {
                for (auto fj : IntersectResult_2)
                {
                    if ((result2.find(fj) != result2.end()) && (fi == fj) && (FinalResult1[k] == make_pair(0, 0)))
                    {
                        FinalResult1[k] = make_pair(result0_2[fi], result2[fj]);
                    }
                    k++;
                }
            }
        }
    }

    if (num == 5)
    {
        vector<string> Result_0;
        vector<string> Result_1;
        vector<string> Result_2;
        vector<string> Result_3;
        vector<string> Result_4;

        vector<pair<string, int>> F_0;
        vector<pair<string, int>> F_1;
        vector<pair<string, int>> F_2;
        vector<pair<string, int>> F_3;
        vector<pair<string, int>> F_4;

        int len2 = 0, len3 = 0, len4 = 0;
        ocall_read_eneq2(&len2, ein2);
        ocall_read_eneq3(&len3, ein3);
        ocall_read_eneq4(&len4, ein4);
        map<string, int> result2, result3, result4;
        vector<bool> ResultVector_2(len2, false), ResultVector_3(len3, false), ResultVector_4(len4, false);
        vector<string> p_decode_2(len2), p_decode_3(len3), p_decode_4(len4);
        vector<string> IntersectResult_2, IntersectResult_3, IntersectResult_4;

        for (int p = 0; p < len1; p++)
        {
            string enindex = ein1[p];
            string p_decode_base64 = base64_decode(enindex);
            string p_decode = aes_256_cbc_decode(cbc_key2, iv1, p_decode_base64);
            p_decode_1[p] = p_decode;
            cscbf.insertion(to_string(1), p_decode);

            if (cscbf.obfquery(0, p_decode) == 1)
            {
                ResultVector_1[p] = 1;
                result1[p_decode] = p;
            }
        }

        for (int p = 0; p < len0; p++)
        {
            if (cscbf.obfquery(1, p_decode_0[p]) == 1)
            {
                ResultVector_0[p] = 1;
                result0[p_decode_0[p]] = p;
            }
        }

        for (int p = 0; p < len0; p++)
        {
            if (ResultVector_0[p])
            {
                Result_0.push_back(p_decode_0[p]);
            }
            else
            {
                Result_0.push_back("0");
            }
        }

        count = 0;
        for (int k = 0; k < Result_0.size(); k++)
        {
            if (Result_0[k] != "0")
            {
                F_0.push_back(make_pair(Result_0[k], count));
                count++;
            }
            else
            {
                F_0.push_back(make_pair("000", -1));
            }
        }

        int chunknumber = F_0.size() / count + 1;
        vector<vector<pair<string, int>>> Chunks0(chunknumber);
        for (int h = 0; h < chunknumber; h++)
        {
            for (int j = 0; (j < count) && (h * count + j < F_0.size()); j++)
            {
                Chunks0[h].push_back(F_0[h * count + j]);
            }
        }

        while (Chunks0.back().size() < count)
        {
            Chunks0.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks0[h], count);
        }

        IntersectResult_0.resize(count, "0");
        for (int h = 0; h < chunknumber; h++)
        {
            for (int l = 0; l < count; l++)
            {
                if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                {
                    IntersectResult_0[l] = Chunks0[h][l].first;
                }
            }
        }

        for (int p = 0; p < len1; p++)
        {
            if (ResultVector_1[p])
            {
                Result_1.push_back(p_decode_1[p]);
            }
            else
            {
                Result_1.push_back("0");
            }
        }

        count = 0;
        for (int k = 0; k < Result_1.size(); k++)
        {
            if (Result_1[k] != "0")
            {
                F_1.push_back(make_pair(Result_1[k], count));
                count++;
            }
            else
            {
                F_1.push_back(make_pair("000", -1));
            }
        }

        chunknumber = F_1.size() / count + 1;
        vector<vector<pair<string, int>>> Chunks1(chunknumber);
        for (int h = 0; h < chunknumber; h++)
        {
            for (int j = 0; (j < count) && (h * count + j < F_1.size()); j++)
            {
                Chunks1[h].push_back(F_1[h * count + j]);
            }
        }

        while (Chunks1.back().size() < count)
        {
            Chunks1.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks1[h], count);
        }

        IntersectResult_1.resize(count, "0");
        for (int h = 0; h < chunknumber; h++)
        {
            for (int l = 0; l < count; l++)
            {
                if (Chunks1[h][l].first != "000" && IntersectResult_1[l] == "0")
                {
                    IntersectResult_1[l] = Chunks1[h][l].first;
                }
            }
        }

        vector<pair<int, int>> FinalResult(count, make_pair(0, 0));
        for (auto fi : IntersectResult_0)
        {
            int k = 0;
            if (result0.find(fi) != result0.end())
            {
                for (auto fj : IntersectResult_1)
                {
                    if ((result1.find(fj) != result1.end()) && (fi == fj) && (FinalResult[k] == make_pair(0, 0)))
                    {
                        FinalResult[k] = make_pair(result0[fi], result1[fj]);
                    }
                    k++;
                }
            }
        }

        vector<vector<string>> Result_x = {Result_2, Result_3, Result_4};
        vector<vector<bool>> ResultVectors = {ResultVector_2, ResultVector_3, ResultVector_4};
        vector<vector<string>> p_decodes = {p_decode_2, p_decode_3, p_decode_4};
        vector<vector<string>> IntersectResults = {IntersectResult_2, IntersectResult_3, IntersectResult_4};
        vector<map<string, int>> results = {result2, result3, result4};
        vector<vector<pair<string, int>>> Fs = {F_2, F_3, F_4};
        vector<int> lens = {len2, len3, len4};
        vector<string> ivs = {iv2, iv3, iv4};

        for (int tbl = 0; tbl < 3; tbl++)
        {
            for (int p = 0; p < lens[tbl]; p++)
            {
                string enindex;
                if (tbl == 0)
                {
                    enindex = ein2[p];
                }
                if (tbl == 1)
                {
                    enindex = ein3[p];
                }
                if (tbl == 2)
                {
                    enindex = ein4[p];
                }
                string p_decode_base64 = base64_decode(enindex);
                string p_decode = aes_256_cbc_decode(cbc_key2, ivs[tbl], p_decode_base64);
                p_decodes[tbl][p] = p_decode;
                cscbf.insertion(to_string(tbl + 2), p_decode);
                if (cscbf.obfquery(0, p_decode) == 1)
                {
                    ResultVectors[tbl][p] = 1;
                    results[tbl][p_decode] = p;
                }
            }

            ResultVector_0.assign(len0, false);
            result0.clear();

            for (int p = 0; p < len0; p++)
            {
                if (cscbf.obfquery(tbl + 2, p_decode_0[p]) == 1)
                {
                    ResultVector_0[p] = 1;
                    result0[p_decode_0[p]] = p;
                }
            }

            Result_0.clear();
            for (int p = 0; p < len0; p++)
            {
                if (ResultVector_0[p])
                {
                    Result_0.push_back(p_decode_0[p]);
                }
                else
                {
                    Result_0.push_back("0");
                }
            }
            count = 0;
            F_0.clear();
            for (int k = 0; k < Result_0.size(); k++)
            {
                if (Result_0[k] != "0")
                {
                    F_0.push_back(make_pair(Result_0[k], count));
                    count++;
                }
                else
                {
                    F_0.push_back(make_pair("000", -1));
                }
            }

            chunknumber = F_0.size() / count + 1;
            Chunks0 = vector<vector<pair<string, int>>>(chunknumber);
            for (int h = 0; h < chunknumber; h++)
            {
                for (int j = 0; (j < count) && (h * count + j < F_0.size()); j++)
                {
                    Chunks0[h].push_back(F_0[h * count + j]);
                }
            }

            while (Chunks0.back().size() < count)
            {
                Chunks0.back().push_back(make_pair("000", -1));
            }

            for (int h = 0; h < chunknumber; h++)
            {
                Oblivious(Chunks0[h], count);
            }

            IntersectResult_0.clear();
            IntersectResult_0.resize(count, "0");

            for (int h = 0; h < chunknumber; h++)
            {
                for (int l = 0; l < count; l++)
                {
                    if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                    {
                        IntersectResult_0[l] = Chunks0[h][l].first;
                    }
                }
            }

            for (int p = 0; p < lens[tbl]; p++)
            {
                if (ResultVectors[tbl][p])
                {
                    Result_x[tbl].push_back(p_decodes[tbl][p]);
                }
                else
                {
                    Result_x[tbl].push_back("0");
                }
            }

            count = 0;

            for (int k = 0; k < Result_x[tbl].size(); k++)
            {
                if (Result_x[tbl][k] != "0")
                {
                    Fs[tbl].push_back(make_pair(Result_x[tbl][k], count));
                    count++;
                }
                else
                {
                    Fs[tbl].push_back(make_pair("000", -1));
                }
            }

            chunknumber = Fs[tbl].size() / count + 1;

            vector<vector<pair<string, int>>> Chunks(chunknumber);
            for (int h = 0; h < chunknumber; h++)
            {
                for (int j = 0; (j < count) && (h * count + j < Fs[tbl].size()); j++)
                {
                    Chunks[h].push_back(Fs[tbl][h * count + j]);
                }
            }

            while (Chunks.back().size() < count)
            {
                Chunks.back().push_back(make_pair("000", -1));
            }

            for (int h = 0; h < chunknumber; h++)
            {
                Oblivious(Chunks[h], count);
            }

            IntersectResults[tbl].resize(count, "0");
            for (int h = 0; h < chunknumber; h++)
            {
                for (int l = 0; l < count; l++)
                {
                    if (Chunks[h][l].first != "000" && IntersectResults[tbl][l] == "0")
                    {
                        IntersectResults[tbl][l] = Chunks[h][l].first;
                    }
                }
            }

            vector<pair<int, int>> FinalResult_temp(count, make_pair(0, 0));

            for (auto fi : IntersectResult_0)
            {
                int k = 0;
                if (result0.find(fi) != result0.end())
                {
                    for (auto fj : IntersectResults[tbl])
                    {
                        if ((results[tbl].find(fj) != results[tbl].end()) && (fi == fj) && (FinalResult_temp[k] == make_pair(0, 0)))
                        {
                            FinalResult_temp[k] = make_pair(result0[fi], results[tbl][fj]);
                        }
                        k++;
                    }
                }
            }
        }
    }

    if (num == 10)
    {
        vector<string> Result_0, Result_1, Result_2, Result_3, Result_4, Result_5, Result_6, Result_7, Result_8, Result_9;
        vector<pair<string, int>> F_0, F_1, F_2, F_3, F_4, F_5, F_6, F_7, F_8, F_9;
        vector<string> IntersectResult_2, IntersectResult_3, IntersectResult_4, IntersectResult_5, IntersectResult_6, IntersectResult_7, IntersectResult_8, IntersectResult_9;

        int len1 = 0, len2 = 0, len3 = 0, len4 = 0, len5 = 0, len6 = 0, len7 = 0, len8 = 0, len9 = 0;
        ocall_read_eneq1(&len1, ein1);
        ocall_read_eneq2(&len2, ein2);
        ocall_read_eneq3(&len3, ein3);
        ocall_read_eneq4(&len4, ein4);
        ocall_read_eneq5(&len5, ein5);
        ocall_read_eneq6(&len6, ein6);
        ocall_read_eneq7(&len7, ein7);
        ocall_read_eneq8(&len8, ein8);
        ocall_read_eneq9(&len9, ein9);

        map<string, int> result1, result2, result3, result4, result5, result6, result7, result8, result9;
        vector<bool> ResultVector_1(len1, false), ResultVector_2(len2, false), ResultVector_3(len3, false), ResultVector_4(len4, false),
            ResultVector_5(len5, false), ResultVector_6(len6, false), ResultVector_7(len7, false), ResultVector_8(len8, false),
            ResultVector_9(len9, false);
        vector<string> p_decode_1(len1), p_decode_2(len2), p_decode_3(len3), p_decode_4(len4), p_decode_5(len5), p_decode_6(len6),
            p_decode_7(len7), p_decode_8(len8), p_decode_9(len9);
        vector<string> IntersectResult_0;

        for (int p = 0; p < len1; p++)
        {
            string enindex = ein1[p];
            string p_decode_base64 = base64_decode(enindex);
            string p_decode = aes_256_cbc_decode(cbc_key2, iv1, p_decode_base64);
            p_decode_1[p] = p_decode;
            cscbf.insertion(to_string(1), p_decode);

            if (cscbf.obfquery(0, p_decode) == 1)
            {
                ResultVector_1[p] = 1;
                result1[p_decode] = p;
            }
        }

        for (int p = 0; p < len0; p++)
        {
            if (cscbf.obfquery(1, p_decode_0[p]) == 1)
            {
                ResultVector_0[p] = 1;
                result0[p_decode_0[p]] = p;
            }
        }

        for (int p = 0; p < len0; p++)
        {
            if (ResultVector_0[p])
            {
                Result_0.push_back(p_decode_0[p]);
            }
            else
            {
                Result_0.push_back("0");
            }
        }

        int count = 0;
        for (int k = 0; k < Result_0.size(); k++)
        {
            if (Result_0[k] != "0")
            {
                F_0.push_back(make_pair(Result_0[k], count));
                count++;
            }
            else
            {
                F_0.push_back(make_pair("000", -1));
            }
        }

        int chunknumber = F_0.size() / count + 1;
        vector<vector<pair<string, int>>> Chunks0(chunknumber);
        for (int h = 0; h < chunknumber; h++)
        {
            for (int j = 0; (j < count) && (h * count + j < F_0.size()); j++)
            {
                Chunks0[h].push_back(F_0[h * count + j]);
            }
        }

        while (Chunks0.back().size() < count)
        {
            Chunks0.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks0[h], count);
        }

        IntersectResult_0.resize(count, "0");
        for (int h = 0; h < chunknumber; h++)
        {
            for (int l = 0; l < count; l++)
            {
                if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                {
                    IntersectResult_0[l] = Chunks0[h][l].first;
                }
            }
        }

        for (int p = 0; p < len1; p++)
        {
            if (ResultVector_1[p])
            {
                Result_1.push_back(p_decode_1[p]);
            }
            else
            {
                Result_1.push_back("0");
            }
        }

        count = 0;
        for (int k = 0; k < Result_1.size(); k++)
        {
            if (Result_1[k] != "0")
            {
                F_1.push_back(make_pair(Result_1[k], count));
                count++;
            }
            else
            {
                F_1.push_back(make_pair("000", -1));
            }
        }

        chunknumber = F_1.size() / count + 1;
        vector<vector<pair<string, int>>> Chunks1(chunknumber);
        for (int h = 0; h < chunknumber; h++)
        {
            for (int j = 0; (j < count) && (h * count + j < F_1.size()); j++)
            {
                Chunks1[h].push_back(F_1[h * count + j]);
            }
        }

        while (Chunks1.back().size() < count)
        {
            Chunks1.back().push_back(make_pair("000", -1));
        }

        for (int h = 0; h < chunknumber; h++)
        {
            Oblivious(Chunks1[h], count);
        }

        IntersectResult_1.resize(count, "0");
        for (int h = 0; h < chunknumber; h++)
        {
            for (int l = 0; l < count; l++)
            {
                if (Chunks1[h][l].first != "000" && IntersectResult_1[l] == "0")
                {
                    IntersectResult_1[l] = Chunks1[h][l].first;
                }
            }
        }

        vector<pair<int, int>> FinalResult(count, make_pair(0, 0));
        for (auto fi : IntersectResult_0)
        {
            int k = 0;
            if (result0.find(fi) != result0.end())
            {
                for (auto fj : IntersectResult_1)
                {
                    if ((result1.find(fj) != result1.end()) && (fi == fj) && (FinalResult[k] == make_pair(0, 0)))
                    {
                        FinalResult[k] = make_pair(result0[fi], result1[fj]);
                    }
                    k++;
                }
            }
        }

        vector<vector<string>> Results = {Result_2, Result_3, Result_4, Result_5, Result_6, Result_7, Result_8, Result_9};
        vector<vector<bool>> ResultVectors = {ResultVector_2, ResultVector_3, ResultVector_4, ResultVector_5, ResultVector_6, ResultVector_7, ResultVector_8, ResultVector_9};
        vector<vector<string>> p_decodes = {p_decode_2, p_decode_3, p_decode_4, p_decode_5, p_decode_6, p_decode_7, p_decode_8, p_decode_9};
        vector<map<string, int>> results = {result2, result3, result4, result5, result6, result7, result8, result9};
        vector<vector<pair<string, int>>> Fs = {F_2, F_3, F_4, F_5, F_6, F_7, F_8, F_9};
        vector<int> lens = {len2, len3, len4, len5, len6, len7, len8, len9};
        vector<string> ivs = {iv2, iv3, iv4, iv5, iv6, iv7, iv8, iv9};
        vector<vector<string>> IntersectResults = {
            IntersectResult_2, IntersectResult_3, IntersectResult_4,
            IntersectResult_5, IntersectResult_6, IntersectResult_7,
            IntersectResult_8, IntersectResult_9};

        for (int tbl = 0; tbl < 8; tbl++)
        {
            for (int p = 0; p < lens[tbl]; p++)
            {
                string enindex;
                if (tbl == 0)
                {
                    enindex = ein2[p];
                }
                if (tbl == 1)
                {
                    enindex = ein3[p];
                }
                if (tbl == 2)
                {
                    enindex = ein4[p];
                }
                if (tbl == 3)
                {
                    enindex = ein5[p];
                }
                if (tbl == 4)
                {
                    enindex = ein6[p];
                }
                if (tbl == 5)
                {
                    enindex = ein7[p];
                }
                if (tbl == 6)
                {
                    enindex = ein8[p];
                }
                if (tbl == 7)
                {
                    enindex = ein9[p];
                }

                string p_decode_base64 = base64_decode(enindex);
                string p_decode = aes_256_cbc_decode(cbc_key2, ivs[tbl], p_decode_base64);
                p_decodes[tbl][p] = p_decode;
                cscbf.insertion(to_string(tbl + 2), p_decode);

                if (cscbf.obfquery(0, p_decode) == 1)
                {
                    ResultVectors[tbl][p] = 1;
                    results[tbl][p_decode] = p;
                }
            }

            ResultVector_0.assign(len0, false);
            result0.clear();

            for (int p = 0; p < len0; p++)
            {
                if (cscbf.obfquery(tbl + 2, p_decode_0[p]) == 1)
                {
                    ResultVector_0[p] = 1;
                    result0[p_decode_0[p]] = p;
                }
            }

            Result_0.clear();
            for (int p = 0; p < len0; p++)
            {
                if (ResultVector_0[p])
                {
                    Result_0.push_back(p_decode_0[p]);
                }
                else
                {
                    Result_0.push_back("0");
                }
            }

            count = 0;
            F_0.clear();
            for (int k = 0; k < Result_0.size(); k++)
            {
                if (Result_0[k] != "0")
                {
                    F_0.push_back(make_pair(Result_0[k], count));
                    count++;
                }
                else
                {
                    F_0.push_back(make_pair("000", -1));
                }
            }

            chunknumber = F_0.size() / count + 1;
            Chunks0 = vector<vector<pair<string, int>>>(chunknumber);

            for (int h = 0; h < chunknumber; h++)
            {
                for (int j = 0; (j < count) && (h * count + j < F_0.size()); j++)
                {
                    Chunks0[h].push_back(F_0[h * count + j]);
                }
            }

            while (Chunks0.back().size() < count)
            {
                Chunks0.back().push_back(make_pair("000", -1));
            }

            for (int h = 0; h < chunknumber; h++)
            {
                Oblivious(Chunks0[h], count);
            }

            IntersectResult_0.clear();
            IntersectResult_0.resize(count, "0");

            for (int h = 0; h < chunknumber; h++)
            {
                for (int l = 0; l < count; l++)
                {
                    if (Chunks0[h][l].first != "000" && IntersectResult_0[l] == "0")
                    {
                        IntersectResult_0[l] = Chunks0[h][l].first;
                    }
                }
            }

            for (int p = 0; p < lens[tbl]; p++)
            {
                if (ResultVectors[tbl][p])
                {
                    Results[tbl].push_back(p_decodes[tbl][p]);
                }
                else
                {
                    Results[tbl].push_back("0");
                }
            }

            count = 0;

            for (int k = 0; k < Results[tbl].size(); k++)
            {
                if (Results[tbl][k] != "0")
                {
                    Fs[tbl].push_back(make_pair(Results[tbl][k], count));
                    count++;
                }
                else
                {
                    Fs[tbl].push_back(make_pair("000", -1));
                }
            }

            chunknumber = Fs[tbl].size() / count + 1;

            vector<vector<pair<string, int>>> Chunks(chunknumber);

            for (int h = 0; h < chunknumber; h++)
            {
                for (int j = 0; (j < count) && (h * count + j < Fs[tbl].size()); j++)
                {
                    Chunks[h].push_back(Fs[tbl][h * count + j]);
                }
            }

            while (Chunks.back().size() < count)
            {
                Chunks.back().push_back(make_pair("000", -1));
            }

            for (int h = 0; h < chunknumber; h++)
            {
                Oblivious(Chunks[h], count);
            }

            IntersectResults[tbl].resize(count, "0");

            for (int h = 0; h < chunknumber; h++)
            {
                for (int l = 0; l < count; l++)
                {
                    if (Chunks[h][l].first != "000" && IntersectResults[tbl][l] == "0")
                    {
                        IntersectResults[tbl][l] = Chunks[h][l].first;
                    }
                }
            }
            int count1 = 0;
            vector<pair<int, int>> FinalResult_temp(count, make_pair(0, 0));
            for (auto fi : IntersectResult_0)
            {
                int k = 0;
                if (result0.find(fi) != result0.end())
                {
                    for (auto fj : IntersectResults[tbl])
                    {
                        if ((results[tbl].find(fj) != results[tbl].end()) && (fi == fj) && (FinalResult_temp[k] == make_pair(0, 0)))
                        {
                            FinalResult_temp[k] = make_pair(result0[fi], results[tbl][fj]);
                            count1++;
                        }
                        k++;
                    }
                }
            }
            printf("The value of count1 is: %d\n", count1);
        }
    }

    e2 = sgx_clock();
    printf("\nsbf(obli)执行时间: %f us\n", (double)((e2 - s2)));
    ocall_close_enquery();
    ocall_close_result();
}
