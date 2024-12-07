#pragma once


#include "SEAL-4.1/seal/seal.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std;
using namespace seal;

inline void save_pk(PublicKey& pk, string& file) {
	ofstream of(file, ios::binary);
	if (of.is_open()) {
		pk.save(of);
		of.close();
	}
	else {
		cerr << "File Open Error! (Public Key Saving File)\n";
	}
}

inline PublicKey load_pk(string& file, SEALContext& context) {
	PublicKey pk;
	ifstream inf(file, ios::binary);
	if (inf.is_open()) {
		pk.load(context, inf);
		inf.close();
	}
	else {
		cerr << "File Open Error! (Public Key Saving File)\n";
	}
	return pk;
}

inline void save_sk(SecretKey& sk, string& file) {
	ofstream of(file, ios::binary);
	if (of.is_open()) {
		sk.save(of);
		of.close();
	}
	else {
		cerr << "File Open Error! (Secret Key Saving File)\n";
	}
}

inline SecretKey load_sk(string& file, SEALContext& context) {
	SecretKey sk;
	ifstream inf(file, ios::binary);
	if (inf.is_open()) {
		sk.load(context, inf);
		inf.close();
	}
	else {
		cerr << "File Open Error! (Secret Key Saving File)\n";
	}
	return sk;
}

inline void save_rk(RelinKeys& rk, string& file) {
	ofstream of(file, ios::binary);
	if (of.is_open()) {
		rk.save(of);
		of.close();
	}
	else {
		cerr << "File Open Error! (Relin Key Saving File)\n";
	}
}

inline RelinKeys load_rk(string& file, SEALContext& context) {
	RelinKeys rk;
	ifstream inf(file, ios::binary);
	if (inf.is_open()) {
		rk.load(context, inf);
		inf.close();
	}
	else {
		cerr << "File Open Error! (Relin Key Saving File)\n";
	}
	return rk;
}

inline void save_gk(GaloisKeys& gk, string& file) {
	ofstream of(file, ios::binary);
	if (of.is_open()) {
		gk.save(of);
		of.close();
	}
	else {
		cerr << "File Open Error! (Galois Key Saving File)\n";
	}
}

inline GaloisKeys load_gk(string& file, SEALContext& context) {
	GaloisKeys gk;
	ifstream inf(file, ios::binary);
	if (inf.is_open()) {
		gk.load(context, inf);
		inf.close();
	}
	else {
		cerr << "File Open Error! (Galois Key Saving File)\n";
	}
	return gk;
}

inline bool is_zero(const vector<uint64_t>& result) {
	for (size_t i = 0; i < result.size()/2; i+=4) {
		if (result[i] == 0) {
			return true;
		}
	}
	return false;
}

inline string vectortostring(vector<uint64_t>& vec) {
	string result;
	for (uint64_t num : vec) {
		result.push_back(static_cast<char>(num)); // 각 uint64_t 값을 char로 변환
	}
	return result;
}