#include <bits/stdc++.h>
#include <google/sparse_hash_map>
#include <iostream>
using google::sparse_hash_map; // namespace where class lives by default
using std::cout;
using std::endl;

struct eqstr {
    bool operator()(const char* s1, const char* s2) const
    {
        return (s1 == s2) || (s1 && s2 && strcmp(s1, s2) == 0);
    }
};

int main()
{
    sparse_hash_map<const char*, int> months;

    months["january"] = 31;
    months["february"] = 28;
    months["march"] = 31;
    months["april"] = 30;
    months["may"] = 31;
    months["june"] = 30;
    months["july"] = 31;
    months["august"] = 31;
    months["september"] = 30;
    months["october"] = 31;
    months["november"] = 30;
    months["december"] = 31;

    auto current = months.find("december");
    cout << months.size() << endl;
    cout << current->first << endl;
    cout << current->second << endl;
    current->second = 35;
    current = months.find("december");
    cout << current->second << endl;
    cout << months.size() << endl;

    if (months.find("decber") != months.end()) {
        cout << "error" << endl;
    }
    cout << months.size() << endl;
}
