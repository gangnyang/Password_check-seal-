#include "SEALtest.h"
#include "jdbc/mysql_driver.h"
#include "jdbc/mysql_connection.h"
#include "jdbc/cppconn/prepared_statement.h"

vector<uint32_t> read_file(string& file_name) {
	// Read file
	ifstream file(file_name);
	vector<uint32_t> passwords;
	string line;
	if (file.is_open()) {
		while (getline(file, line)) {
			if (!line.empty()) {
				if (line.length() < PADDING_LENGTH) { // password padding
					size_t padding = PADDING_LENGTH - line.length();
					line += string(padding, 0);
				}
				else if (line.length() > PADDING_LENGTH) {
					line = line.substr(0, PADDING_LENGTH);
				}

				for (size_t i = 0; i < line.length(); i += 2) {
					uint32_t part = 0;
					for (size_t j = 0; j < 2; j++) {
						if (i + j < line.length()) {
							part |= static_cast<uint32_t>(line[i + j]) << (8 * j);
						}
					}
					passwords.emplace_back(part);
				}
			}
		}
		cout << "File Opening... Success.\n";
		file.close();
	}
	else {
		cerr << "File Open Error! (Password File)\n";
	}
	return passwords;
}

int main() {

	// BGV default setting
	EncryptionParameters params(scheme_type::bfv);
	size_t poly_modulus_degree = 16384;
	params.set_poly_modulus_degree(poly_modulus_degree);
	params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

	SEALContext context(params);
	KeyGenerator keygen(context);
	PublicKey pk;
	RelinKeys rk;
	GaloisKeys gk;
	string pk_file = "public_key_16384.seal";
	string rk_file = "relin_key_16384.seal";
	string gk_file = "galois_key_16384.seal";


	if (filesystem::exists(pk_file)) {
		pk = load_pk(pk_file, context);
		cout << "Loading saved Public Key ... Success.\n";
	}
	else {
		keygen.create_public_key(pk);
		save_pk(pk, pk_file);
		cout << "Make new Public Key and save... Success.\n";
	}

	if (filesystem::exists(rk_file)) {
		rk = load_rk(rk_file, context);
		cout << "Loading saved Relin Key ... Success.\n";
	}
	else {
		keygen.create_relin_keys(rk);
		save_rk(rk, rk_file);
		cout << "Make new Relin Key and save... Success.\n";
	}

	if (filesystem::exists(gk_file)) {
		gk = load_gk(gk_file, context);
		cout << "Loading saved Galois Key ... Success.\n";
	}
	else {
		keygen.create_galois_keys(gk);
		save_gk(gk, gk_file);
		cout << "Make new Galois Key and save... Success.\n";
	}

	Encryptor encryptor(context, pk);
	Evaluator evaluator(context);

	BatchEncoder encoder(context);
	size_t slot_count = encoder.slot_count();
	size_t row_size = slot_count / 2;
	string fn = "custom_generated_passwords.csv";
	vector<uint32_t> passwords = read_file(fn);

	try { // SQL CONNECTION
		sql::mysql::MySQL_Driver* driver = sql::mysql::get_driver_instance();
		sql::Connection* con(driver->connect("tcp://127.0.0.1:3306", "root", "sang8429"));

		con->setSchema("crypto");

		cout << "Connecting to DB ... Success.\n";

		unique_ptr<sql::PreparedStatement> pstmt(con->prepareStatement("INSERT INTO leaked_pw (encrypted_pw, pw) VALUES(?, ?)"));


		vector<uint64_t> data(slot_count, 0);

		for (size_t i = 0; i < passwords.size(); i += row_size) {
			for (size_t j = 0; j < row_size; j++) {
				if (i + j < passwords.size()) {
					data[j] = passwords[i + j];
				}
				else {
					data[j] = 0;
				}
			}

			Plaintext plaintext;
			encoder.encode(data, plaintext);

			Ciphertext encrypted;
			encryptor.encrypt(plaintext, encrypted);

			stringstream pass_ss;
			encrypted.save(pass_ss);

			stringstream password_ss;
			for (size_t k = i; k < i + row_size && k < passwords.size(); k++) {
				password_ss << passwords[k] << " ";
			}

			pstmt->setBlob(1, &pass_ss);
			pstmt->setString(2, password_ss.str());
			pstmt->execute();

			cout << "INSERT COMPLETE (" << password_ss.str() << ")\n";

		}

		delete con;
	}
	catch (sql::SQLException& e) {
		cerr << "MySQL Error: " << e.what() << "\n";
		return 1; // error
	}
	cout << "SQL INSERT OPERATION DONE WELL.\n";
}