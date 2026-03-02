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

#define NUM_DB 10
#define HASH_NUM 3
#define REP_TIME 3
#define PART_NUM 62
#define TOTAL_CAP 60000000

using namespace std;

int main() {

    // -------------------- Initialize CSCBF --------------------
    // Parameters:
    // REP_TIME  - number of repetitions
    // PART_NUM  - number of partitions
    // TOTAL_CAP - total capacity
    // HASH_NUM  - number of hash functions
    // NUM_DB    - number of databases / sets
    CSCBF cscbf(REP_TIME, PART_NUM, TOTAL_CAP, HASH_NUM, NUM_DB);

    // -------------------- Data insertion phase --------------------
    // Read files set_0 ~ set_9 and insert their elements into CSCBF
    string file_prefix = "./data/cmp_data/set_";
    string lines;
    lines.clear();
    int j = 0;

    for (int i = 0; i < NUM_DB; i++) {
        string file_name = file_prefix + to_string(i);
        ifstream file(file_name);

        // Check whether the file is successfully opened
        if (!file.is_open()) {
            cout << "open file error!" << endl;
            return 0;
        }

        // Read each line from the file and insert it into CSCBF
        while (getline(file, lines)) {
            if (file.eof()) {
                break;
            }
            cscbf.insertion(to_string(i), lines);
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

    set<string> s0; s0.clear();
    set<string> s1; s1.clear();
    set<string> s2; s2.clear();
    set<string> s3; s3.clear();

    string element;
    element.clear();
    size_t set_ID;

    map<string, set<size_t>> ground_truth;

    while (getline(new_query, line)) {
        if (new_query.eof()) {
            break;
        }

        // Parse the current line and insert the element into the query set
        sstr << line;
        sstr >> element;
        query_element.insert(element);

        // Clear the stream state for the next iteration
        sstr.clear();
    }

    /*----------------------------------------------------------------------------------------------------*/
    // -------------------- Query phase --------------------
    // For each query element, check whether it exists in all sets
    chrono::time_point<chrono::high_resolution_clock> t0 = chrono::high_resolution_clock::now();

    set<string> query_result;
    query_result.clear();

    for (auto &ele : query_element) {
        int res = 1;

        // Check whether the element exists in every set
        for (int set_ID = 1; set_ID < NUM_DB; set_ID++) {
            int cscbf_res = cscbf.query(set_ID, ele);
            res &= cscbf_res;

            // Stop early if the element is absent from one set
            if (!res) {
                break;
            }
        }

        // If res is still 1, the element exists in all checked sets
        if (res) {
            query_result.insert(ele);
        }
    }

    chrono::time_point<chrono::high_resolution_clock> t1 = chrono::high_resolution_clock::now();

    // Compute query time in milliseconds
    float time = ((t1 - t0).count() / 1000000.0);
    printf("SBF:The  query time is %f ms\n", time);

    /*----------------------------------------------------------------------------------------------------*/
    // Uncomment the following code if you want to print query results
    // for (const auto &element : query_result)
    // {
    //     std::cout << element << std::endl;
    // }

    system("pause");
    return 0;
}