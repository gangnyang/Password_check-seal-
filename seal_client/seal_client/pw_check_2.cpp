#include "winsockset_client.h"

SOCKET server_socket;

int main() {

	EncryptionParameters params(scheme_type::bfv);
	size_t poly_modulus_degree = 16384;
	params.set_poly_modulus_degree(poly_modulus_degree);
	params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

	SEALContext context(params);
	KeyGenerator keygen(context);
	PublicKey pk;
	SecretKey sk;
	RelinKeys rk;
	GaloisKeys gk;
	string pk_file = "public_key_16384.seal";
	string sk_file = "secret_key_16384.seal";
	string rk_file = "relin_key_16384.seal";
	string gk_file = "galois_key_16384.seal";

	if (filesystem::exists(pk_file)) {
		pk = load_pk(pk_file, context);
		cout << "Loading Public Key... Success.\n";
	}
	else {
		keygen.create_public_key(pk);
		save_pk(pk, pk_file);
		cout << "Make new Public Key and save... Success.\n";
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
	Decryptor decryptor(context, sk);

	BatchEncoder encoder(context);
	size_t slot_count = encoder.slot_count();
	size_t row_size = slot_count / 2;
	cout << "Input your password: ";
	string input_password_str;
	cin >> input_password_str;
	// 비밀번호 입력을 완료하자마자 시간 측정 시작
	std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
	if (input_password_str.length() < PADDING_LENGTH) {
		size_t padding = PADDING_LENGTH - input_password_str.length();
		input_password_str += string(padding, 0);
	}
	else if (input_password_str.length() > PADDING_LENGTH) {
		input_password_str = input_password_str.substr(0, PADDING_LENGTH);
	}
	vector<uint32_t> input_password;
	for (size_t i = 0; i < input_password_str.length(); i += 2) {
		uint32_t part = 0;
		for (size_t j = 0; j < 2; j++) {
			if (i + j < input_password_str.length()) {
				part |= static_cast<uint32_t>(input_password_str[i + j]) << (8 * j);
			}
		}
		input_password.emplace_back(part);
	}

	vector<uint64_t> input_password_vec1(slot_count, 0);
	vector<uint64_t> input_password_vec2(slot_count, 0);
	vector<uint64_t> input_password_vec3(slot_count, 0);
	vector<uint64_t> input_password_vec4(slot_count, 0);
	vector<uint64_t> input_password_vec5(slot_count, 0);
	vector<uint64_t> input_password_vec6(slot_count, 0);
	vector<uint64_t> input_password_vec7(slot_count, 0);
	vector<uint64_t> input_password_vec8(slot_count, 0);

#pragma omp parallel for
	for (int i = 0; i < row_size; i += 8) {
		input_password_vec1[i] = input_password[0];
		input_password_vec2[i] = input_password[1];
		input_password_vec3[i] = input_password[2];
		input_password_vec4[i] = input_password[3];
		input_password_vec5[i] = input_password[4];
		input_password_vec6[i] = input_password[5];
		input_password_vec7[i] = input_password[6];
		input_password_vec8[i] = input_password[7];
	}

	// Make Ciphertext
	Plaintext plaintext1, plaintext2, plaintext3, plaintext4, plaintext5, plaintext6, plaintext7, plaintext8;
	for (char ch : input_password_vec1) {
		if (ch == '\0') {
			cout << "0 ";
		}
		else {
			cout << ch << " ";
		}
	}
	cout << "\n";

	if (context.first_context_data()->qualifiers().using_batching) {
		cout << "Batching is enabled!" << endl;
	}
	else {
		cerr << "Batching is not enabled. Check your parameters!" << endl;
	}
	Ciphertext encrypted1, encrypted2, encrypted3, encrypted4, encrypted5, encrypted6, encrypted7, encrypted8;

#pragma omp parallel sections
	{
#pragma omp section
		{
			encoder.encode(input_password_vec1, plaintext1);
			encryptor.encrypt(plaintext1, encrypted1);
		}
#pragma omp section
		{
			encoder.encode(input_password_vec2, plaintext2);
			encryptor.encrypt(plaintext2, encrypted2);
		}
#pragma omp section
		{
			encoder.encode(input_password_vec3, plaintext3);
			encryptor.encrypt(plaintext3, encrypted3);
		}
#pragma omp section
		{
			encoder.encode(input_password_vec4, plaintext4);
			encryptor.encrypt(plaintext4, encrypted4);
		}
#pragma omp section
		{
			encoder.encode(input_password_vec5, plaintext5);
			encryptor.encrypt(plaintext5, encrypted5);
		}
#pragma omp section
		{
			encoder.encode(input_password_vec6, plaintext6);
			encryptor.encrypt(plaintext6, encrypted6);
		}
#pragma omp section
		{
			encoder.encode(input_password_vec7, plaintext7);
			encryptor.encrypt(plaintext7, encrypted7);
		}
#pragma omp section
		{
			encoder.encode(input_password_vec8, plaintext8);
			encryptor.encrypt(plaintext8, encrypted8);
		}
	}


	auto context_data = context.get_context_data(encrypted1.parms_id());
	std::cout << "Current level: " << context_data->chain_index() << "\n";

	auto noise_budget = decryptor.invariant_noise_budget(encrypted1);
	std::cout << "Noise budget: " << noise_budget << " bits\n";

	//---------------------------------------------------------------
	WSADATA wsadata;

	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		cout << "WSA Failed\n";
		return 2;
	}

	server_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	SOCKADDR_IN addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(6226);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	while (1) {
		if (!connect(server_socket, (SOCKADDR*)&addr, sizeof(addr))) break;
	}
	cout << "Connection Complete\n";

	socket_send(encrypted1, server_socket);
	socket_send(encrypted2, server_socket);
	socket_send(encrypted3, server_socket);
	socket_send(encrypted4, server_socket);
	socket_send(encrypted5, server_socket);
	socket_send(encrypted6, server_socket);
	socket_send(encrypted7, server_socket);
	socket_send(encrypted8, server_socket);

	u_long mode = 1;
	ioctlsocket(server_socket, FIONBIO, &mode);

	Ciphertext received;
	while (true) { // 올바르게 전달받을 경우 break
		if (socket_receive(received, context, server_socket) == 2) break;
	}
	Plaintext result_plain;
	decryptor.decrypt(received, result_plain);
	vector<uint64_t> result_vec;
	encoder.decode(result_plain, result_vec);


	if (is_zero(result_vec)) { // 벡터에 0이 있는지 확인
		cout << "Your password is leaked!\n";
	}
	else {
		cout << "Your password is not leaked.\n";
	}

	std::chrono::duration<double>dura = std::chrono::system_clock::now() - start;
	std::cout << "Total Duration of Program Execution: " << dura.count() << "\n";

	closesocket(server_socket);

	WSACleanup();
	return 0;
}