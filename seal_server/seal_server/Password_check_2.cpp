// 2번 프로그램입니다.

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

	Ciphertext received_pw1, received_pw2, received_pw3, received_pw4, received_pw5, received_pw6, received_pw7, received_pw8;
	socket_receive(received_pw1, context, client_socket);
	socket_receive(received_pw2, context, client_socket);
	socket_receive(received_pw3, context, client_socket);
	socket_receive(received_pw4, context, client_socket);
	socket_receive(received_pw5, context, client_socket);
	socket_receive(received_pw6, context, client_socket);
	socket_receive(received_pw7, context, client_socket);
	socket_receive(received_pw8, context, client_socket);

	Decryptor decryptor(context, sk); // 디버깅용

	std::cout << "Received Ciphertext\n";

	auto context_data = context.get_context_data(received_pw1.parms_id());
	std::cout << "Current level: " << context_data->chain_index() << "\n";

	auto noise_budget = decryptor.invariant_noise_budget(received_pw1);
	std::cout << "Noise budget: " << noise_budget << " bits\n";

	Ciphertext encrypted_result;

	omp_set_num_threads(8);

	try { // SQL 연결
		sql::mysql::MySQL_Driver* driver = sql::mysql::get_driver_instance();
		sql::Connection* con(driver->connect("tcp://127.0.0.1:3306", "root", "sang8429"));

		con->setSchema("crypto");

		std::cout << "Connecting to DB ... Success.\n";

		unique_ptr<sql::PreparedStatement> pstmt(con->prepareStatement("SELECT encrypted_pw1, encrypted_pw2, encrypted_pw3, encrypted_pw4, encrypted_pw5, encrypted_pw6, encrypted_pw7, encrypted_pw8 from leaked_pw2 LIMIT 1")); // 한 번만 테스트
		unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

		while (res->next()) {
			istream* bstream1 = res->getBlob("encrypted_pw1");
			istream* bstream2 = res->getBlob("encrypted_pw2");
			istream* bstream3 = res->getBlob("encrypted_pw3");
			istream* bstream4 = res->getBlob("encrypted_pw4");
			istream* bstream5 = res->getBlob("encrypted_pw5");
			istream* bstream6 = res->getBlob("encrypted_pw6");
			istream* bstream7 = res->getBlob("encrypted_pw7");
			istream* bstream8 = res->getBlob("encrypted_pw8");
			Ciphertext squared_result1, squared_result2, squared_result3, squared_result4, squared_result5, squared_result6, squared_result7, squared_result8;
#pragma omp parallel for
			for (int i = 0; i < 8; i++) {
				std::cout << "Thread " << omp_get_thread_num() << " is processing square " << i << "\n";
				Ciphertext db_encrypted_pw, sub_result, squared_result;
				if (i == 0) db_encrypted_pw.load(context, *bstream1);
				else if (i == 1) db_encrypted_pw.load(context, *bstream2);
				else if (i == 2) db_encrypted_pw.load(context, *bstream3);
				else if (i == 3) db_encrypted_pw.load(context, *bstream4);
				else if (i == 4) db_encrypted_pw.load(context, *bstream5);
				else if (i == 5) db_encrypted_pw.load(context, *bstream6);
				else if (i == 6) db_encrypted_pw.load(context, *bstream7);
				else if (i == 7) db_encrypted_pw.load(context, *bstream8);

				if (i == 0) evaluator.sub(db_encrypted_pw, received_pw1, sub_result);
				else if (i == 1) evaluator.sub(db_encrypted_pw, received_pw2, sub_result);
				else if (i == 2) evaluator.sub(db_encrypted_pw, received_pw3, sub_result);
				else if (i == 3) evaluator.sub(db_encrypted_pw, received_pw4, sub_result);
				else if (i == 4) evaluator.sub(db_encrypted_pw, received_pw5, sub_result);
				else if (i == 5) evaluator.sub(db_encrypted_pw, received_pw6, sub_result);
				else if (i == 6) evaluator.sub(db_encrypted_pw, received_pw7, sub_result);
				else if (i == 7) evaluator.sub(db_encrypted_pw, received_pw8, sub_result);


				evaluator.square(sub_result, squared_result);

				std::cout << "After Sqauring\n";

				context_data = context.get_context_data(squared_result.parms_id());
				std::cout << "Current level: " << context_data->chain_index() << "\n";

				noise_budget = decryptor.invariant_noise_budget(squared_result);
				std::cout << "Noise budget: " << noise_budget << " bits\n";

				evaluator.relinearize_inplace(squared_result, rk);
				evaluator.mod_switch_to_next_inplace(squared_result);

#pragma omp critical
				{
					if (i == 0) squared_result1 = squared_result;
					else if (i == 1) squared_result2 = squared_result;
					else if (i == 2) squared_result3 = squared_result;
					else if (i == 3) squared_result4 = squared_result;
					else if (i == 4) squared_result5 = squared_result;
					else if (i == 5) squared_result6 = squared_result;
					else if (i == 6) squared_result7 = squared_result;
					else if (i == 7) squared_result8 = squared_result;
				}
			}

#pragma omp parallel sections // 3단계로 병렬처리
			{
#pragma omp section
				evaluator.add_inplace(squared_result1, squared_result2);

#pragma omp section
				evaluator.add_inplace(squared_result3, squared_result4);

#pragma omp section
				evaluator.add_inplace(squared_result5, squared_result6);

#pragma omp section
				evaluator.add_inplace(squared_result7, squared_result8);
			}

#pragma omp parallel sections
			{
#pragma omp section
				evaluator.add_inplace(squared_result1, squared_result3);

#pragma omp section
				evaluator.add_inplace(squared_result5, squared_result7);
			}
			evaluator.add_inplace(squared_result1, squared_result5);


			size_t rotate_size = 1;

			Ciphertext added_result;
			Ciphertext rotated_result = squared_result1;

			std::cout << "After Relinearize\n";

			context_data = context.get_context_data(rotated_result.parms_id());
			std::cout << "Current level: " << context_data->chain_index() << "\n";

			noise_budget = decryptor.invariant_noise_budget(rotated_result);
			std::cout << "Noise budget: " << noise_budget << " bits\n";

			size_t cnt = 0;
			size_t numofpasswords = 1024; // LOG2(비밀번호 수)만큼 회전 후 곱하면 모든 비밀번호의 정보를 담을 수 있다
			while (numofpasswords > rotate_size * 4) {
				Ciphertext temp_result = rotated_result;
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