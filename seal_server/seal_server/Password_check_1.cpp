// 1번 프로그램입니다. password_check.cpp는 8192일 때 기준 프로그램입니다.

#include "SEALtest.h"
#include "winsockset_server.h"
#include "jdbc/mysql_driver.h"
#include "jdbc/mysql_connection.h"
#include "jdbc/cppconn/prepared_statement.h"

SOCKET server_socket, client_socket;

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
	SecretKey sk;
	string pk_file = "public_key_16384.seal";
	string rk_file = "relin_key_16384.seal";
	string gk_file = "galois_key_16384.seal";
	string sk_file = "secret_key_16384.seal"; // For debugging

	if (filesystem::exists(pk_file)) {
		pk = load_pk(pk_file, context);
		std::cout << "Loading saved Public Key ... Success.\n";
	}
	else {
		keygen.create_public_key(pk);
		save_pk(pk, pk_file);
		std::cout << "Make new Public Key and save... Success.\n";
	}

	if (filesystem::exists(rk_file)) {
		rk = load_rk(rk_file, context);
		std::cout << "Loading saved Relin Key ... Success.\n";
	}
	else {
		keygen.create_relin_keys(rk);
		save_rk(rk, rk_file);
		std::cout << "Make new Relin Key and save... Success.\n";
	}

	if (filesystem::exists(gk_file)) {
		gk = load_gk(gk_file, context);
		std::cout << "Loading saved Galois Key ... Success.\n";
	}
	else {
		keygen.create_galois_keys(gk);
		save_gk(gk, gk_file);
		std::cout << "Make new Galois Key and save... Success.\n";
	}

	if (filesystem::exists(sk_file)) {
		sk = load_sk(sk_file, context);
		cout << "Loading Secret Key... Success.\n";
	}
	else {
		sk = keygen.secret_key();
		save_sk(sk, sk_file);
		cout << "Make new Secret Key and save... Success.\n";
	}

	Encryptor encryptor(context, pk);
	Evaluator evaluator(context);

	BatchEncoder encoder(context);
	size_t slot_count = encoder.slot_count();
	size_t row_size = slot_count / 2;

	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		std::cout << "WSA Failed\n";
		return 2;
	}
	// 소켓 생성
	server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	SOCKADDR_IN addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(6226); // 6226번 포트 사용
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	// 클라이언트 연결을 위한 정보 할당
	if (::bind(server_socket, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		std::cout << "Bind Failed.\n";
		WSACleanup();
		return 1;
	}
	listen(server_socket, SOMAXCONN);

	SOCKADDR_IN client = {};
	int client_size = sizeof(client);

	while (true) {
		client_socket = accept(server_socket, (SOCKADDR*)&client, &client_size);
		if (client_socket == INVALID_SOCKET) {
			std::cout << "Accept failed " << WSAGetLastError() << "\n";
			continue;
		}
		else {
			std::cout << "Connect Success\n";
			std::cout << "Client: " << inet_ntoa(client.sin_addr) << "\n";
			std::cout << "Port: " << ntohs(client.sin_port) << "\n";
			break;
		}
	}

	Ciphertext received_pw;
	socket_receive(received_pw, context, client_socket);

	Decryptor decryptor(context, sk); // 디버깅용

	std::cout << "Received Ciphertext\n";

	auto context_data = context.get_context_data(received_pw.parms_id());
	std::cout << "Current level: " << context_data->chain_index() << "\n";

	auto noise_budget = decryptor.invariant_noise_budget(received_pw);
	std::cout << "Noise budget: " << noise_budget << " bits\n";

	Ciphertext encrypted_result;

	try { // SQL 연결
		sql::mysql::MySQL_Driver* driver = sql::mysql::get_driver_instance();
		sql::Connection* con(driver->connect("tcp://127.0.0.1:3306", "root", "sang8429"));

		con->setSchema("crypto");

		std::cout << "Connecting to DB ... Success.\n";

		unique_ptr<sql::PreparedStatement> pstmt(con->prepareStatement("SELECT encrypted_pw from leaked_pw LIMIT 1")); // 한 번만 테스트
		unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

		while (res->next()) {
			istream* bstream = res->getBlob("encrypted_pw");

			Ciphertext db_encrypted_pw;
			db_encrypted_pw.load(context, *bstream);

			Ciphertext sub_result;
			evaluator.sub(db_encrypted_pw, received_pw, sub_result);

			std::cout << "After Subtraction\n";

			auto context_data = context.get_context_data(sub_result.parms_id());
			std::cout << "Current level: " << context_data->chain_index() << "\n";

			auto noise_budget = decryptor.invariant_noise_budget(sub_result);
			std::cout << "Noise budget: " << noise_budget << " bits\n";


			Ciphertext squared_result; // 서로 빼고 나서 음수랑 양수가 만나 0이 되는 경우를 방지하기 위해 제곱한다
			evaluator.square(sub_result, squared_result);

			std::cout << "After Sqauring\n";

			context_data = context.get_context_data(squared_result.parms_id());
			std::cout << "Current level: " << context_data->chain_index() << "\n";

			noise_budget = decryptor.invariant_noise_budget(squared_result);
			std::cout << "Noise budget: " << noise_budget << " bits\n";

			evaluator.relinearize_inplace(squared_result, rk);
			evaluator.mod_switch_to_next_inplace(squared_result);

			size_t rotate_size = PADDING_LENGTH / 2;

			Ciphertext rotated_result = squared_result;
			Ciphertext temp_result = squared_result;

			std::cout << "After Relinearize and modulus_switching\n";

			context_data = context.get_context_data(rotated_result.parms_id());
			std::cout << "Current level: " << context_data->chain_index() << "\n";

			noise_budget = decryptor.invariant_noise_budget(rotated_result);
			std::cout << "Noise budget: " << noise_budget << " bits\n";

			for (size_t i = 0; i < rotate_size - 1; i++) { // 2글자씩 한 벡터 요소에 담기 때문에 PADDING LENGTH/2 - 1만큼 회전 연산 후 더한다
				evaluator.rotate_rows_inplace(temp_result, 1, gk);
				evaluator.add(rotated_result, temp_result, rotated_result);
			}

			size_t cnt = 0;
			size_t numofpasswords = row_size; // LOG2(비밀번호 수)만큼 회전 후 곱하면 모든 비밀번호의 정보를 담을 수 있다
			while (numofpasswords > rotate_size*4) {
				temp_result = rotated_result;
				evaluator.rotate_rows_inplace(temp_result, numofpasswords / 2, gk);
				evaluator.multiply_inplace(rotated_result, temp_result);
				cnt++;

				Plaintext for_debugging;
				decryptor.decrypt(rotated_result, for_debugging);
				vector<uint64_t> for_debugging_vec(slot_count, 0);
				encoder.decode(for_debugging, for_debugging_vec);

				std::cout << "After Multiplying(Compression)\n";

				context_data = context.get_context_data(rotated_result.parms_id());
				std::cout << "Current level: " << context_data->chain_index() << "\n";

				noise_budget = decryptor.invariant_noise_budget(rotated_result);
				std::cout << "Noise budget: " << noise_budget << " bits\n";

				evaluator.relinearize_inplace(rotated_result, rk);

				if (cnt % 3 != 0) {
					evaluator.mod_switch_to_next_inplace(rotated_result);
				}

				numofpasswords /= 2;
			}

			encrypted_result = rotated_result;
		}

		delete con;
	}
	catch (sql::SQLException& e) {
		cerr << "MySQL Error: " << e.what() << "\n";
		return 1; // error
	}

	std::cout << "Finishing All Process\n";
	context_data = context.get_context_data(encrypted_result.parms_id());
	std::cout << "Current level: " << context_data->chain_index() << "\n";

	noise_budget = decryptor.invariant_noise_budget(encrypted_result);
	std::cout << "Noise budget: " << noise_budget << " bits\n";

	socket_send(encrypted_result, client_socket);
	std::cout << "Sending Complete.\n";

	closesocket(client_socket);
	closesocket(server_socket);

	WSACleanup();
	return 0;
}

//hsjw26227	
//runfj7618
//zfbipd41749