#include <string>
#include <fstream>
#include <set>
#include <map>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <chrono>

#include "BIGSI.h"
#include "CSCBF.h"
#include "BloomFilter.h"

#define NUM_DB 10
#define HASH_NUM 3
#define REP_TIME 3
#define PART_NUM 62
#define TOTAL_CAP 60000000

using namespace std;

int main()
{
    // -------------------- Initialize BIGSI --------------------
    // Parameters:
    // NUM_DB    - number of databases / sets
    // HASH_NUM  - number of hash functions
    // TOTAL_CAP - total capacity of the Bloom filter structure
    BIGSI baseline_bigsi(NUM_DB, HASH_NUM, TOTAL_CAP);

    // -------------------- Data insertion phase --------------------
    // Read files set_0 ~ set_9 and insert their elements into BIGSI
    string file_prefix = "./data/cmp_data/set_";
    string lines;
    lines.clear();
    int j = 0;

    for (int i = 0; i < NUM_DB; i++)
    {
        string file_name = file_prefix + to_string(i);
        ifstream file(file_name);

        // Check whether the file is successfully opened
        if (!file.is_open())
        {
            cout << "open file error!" << endl;
            return 0;
        }

        // Read each line from the file and insert it into BIGSI
        while (getline(file, lines))
        {
            if (file.eof())
            {
                break;
            }
            baseline_bigsi.insertion(i, lines);
            lines.clear();
        }

        file.close();
        file_name.clear();
    }

    /*** query ***/
    // -------------------- Query loading phase --------------------
    // Read all query elements from the query file
    string query_file1 = "./data/cmp_data/query";
    string line;
    line.clear();
    ifstream new_query(query_file1);

    stringstream sstr;
    set<string> query_element;
    query_element.clear();

    string element;
    element.clear();

    size_t set_ID;
    map<string, set<size_t>> ground_truth;

    while (getline(new_query, line))
    {
        if (new_query.eof())
        {
            break;
        }

        // Parse the current line and insert the element into the query set
        sstr << line;
        sstr >> element;
        query_element.insert(element);

        // Clear the stream state for the next iteration
        sstr.clear();
    }

    /*------------------------------------------------------------------------------*/
    // -------------------- Query phase --------------------
    // For each set i (from 1 to 9), compare set 0 with set i
    // and test whether each query element is contained in the
    // corresponding comparison result bit array
    chrono::time_point<chrono::high_resolution_clock> start = chrono::high_resolution_clock::now();

    for (size_t i = 1; i < 10; i++)
    {
        // Initialize a comparison array for the current pair of sets
        std::vector<bool> Cmp_Array(baseline_bigsi.single_capacity, false);

        // Obtain the comparison result between set 0 and set i
        Cmp_Array = baseline_bigsi.query(0, i);

        // Store the query elements that satisfy the membership test
        set<string> query_result;
        query_result.clear();

        for (auto &ele : query_element)
        {
            int res = 1;

            // Compute the Bloom filter hash locations for the current element
            vector<size_t> check_locations = BF_Hash(
                ele,
                baseline_bigsi.k,
                baseline_bigsi.seed,
                baseline_bigsi.single_capacity
            );

            // Check whether all corresponding positions are set to true
            for (auto &location : check_locations)
            {
                res &= Cmp_Array[location];
            }

            // If all positions are true, keep this element in the query result
            if (res)
            {
                query_result.insert(ele);
            }
        }

        // The following code can be enabled if per-pair query time is needed
        // chrono::time_point<chrono::high_resolution_clock> t1 = chrono::high_resolution_clock::now();
        // float time = ((t1 - t0).count() / 1000000.0);
        // printf("The query time of set %d and %d is %f ms\n", 0, i, time);
    }

    chrono::time_point<chrono::high_resolution_clock> end = chrono::high_resolution_clock::now();

    // Compute the total query time in milliseconds
    float time = ((end - start).count() / 1000000.0);
    printf("BF:The  query total time is %f ms\n", time);
    /*------------------------------------------------------------------------------*/

    return 0;
}