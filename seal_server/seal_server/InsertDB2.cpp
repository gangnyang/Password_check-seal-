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
	string pk_file = "public_key_16384.seal";


	if (filesystem::exists(pk_file)) {
		pk = load_pk(pk_file, context);
		cout << "Loading saved Public Key ... Success.\n";
	}
	else {
		keygen.create_public_key(pk);
		save_pk(pk, pk_file);
		cout << "Make new Public Key and save... Success.\n";
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

		unique_ptr<sql::PreparedStatement> pstmt(con->prepareStatement("INSERT INTO leaked_pw2 (encrypted_pw1, encrypted_pw2, encrypted_pw3, encrypted_pw4, encrypted_pw5, encrypted_pw6, encrypted_pw7, encrypted_pw8) VALUES(?, ?, ?, ?, ?, ?, ?, ?)"));


		size_t total_blocks = (passwords.size() + 8191) / 8192; // DB에 들어갈 투플 수 
		vector<uint64_t> data(slot_count, 0); // 비교를 위해 1024개의 비밀번호를 담음
		

		for (size_t block = 0; block < total_blocks; block++) {
			stringstream pass_ss[8];
			for (size_t col = 0; col < 8; col++) {
				vector<uint64_t> data(slot_count, 0); // 비교를 위해 1024개의 비밀번호를 담음
				for (size_t i = 0; i < 1024; i++) {
					size_t index = block * 8192 + col + i * 8; // 8개씩 건너뛰면서 담는다
					if (index < passwords.size()) {
						data[i] = passwords[index]; 
					}
					else {
						data[i] = 0; 
					}
				}

				Plaintext plaintext;
				encoder.encode(data, plaintext);

				Ciphertext encrypted;
				encryptor.encrypt(plaintext, encrypted);

				encrypted.save(pass_ss[col]);

				std::cout << "Encrypted data size: " << pass_ss[col].str().size() << " bytes\n";

				pstmt->setBlob(col + 1, &pass_ss[col]);
			}
			pstmt->execute();
			cout << "INSERT COMPLETE (BLOCK " << block + 1 << ")\n";
		}

		delete con;
	}
	catch (sql::SQLException& e) {
		cerr << "MySQL Error: " << e.what() << "\n";
		return 1; // error
	}
	cout << "SQL INSERT OPERATION DONE WELL.\n";
}