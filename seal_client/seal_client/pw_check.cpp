#include "winsockset_client.h"

SOCKET server_socket;

int main() {

	EncryptionParameters params(scheme_type::bfv);
	size_t poly_modulus_degree = 8192;
	params.set_poly_modulus_degree(poly_modulus_degree);
	params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 40));

	SEALContext context(params);
	KeyGenerator keygen(context);
	PublicKey pk;
	SecretKey sk;
	RelinKeys rk;
	GaloisKeys gk;
	string pk_file = "public_key.seal";
	string sk_file = "secret_key.seal";
	string rk_file = "relin_key.seal";
	string gk_file = "galois_key.seal";

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
	else if(input_password_str.length()>PADDING_LENGTH) {
		input_password_str = input_password_str.substr(0, PADDING_LENGTH);
	}
	vector<uint32_t> input_password;
	for (size_t i = 0; i < input_password_str.length(); i += 4) {
		uint32_t part = 0;
		for (size_t j = 0; j < 4; j++) {
			if (i + j < input_password_str.length()) {
				part |= static_cast<uint32_t>(input_password_str[i + j]) << (8 * j);
			}
		}
		input_password.emplace_back(part);
	}

	vector<uint64_t> input_password_vec(slot_count, 0);
	for (size_t i = 0; i < row_size; i+=4) {
		for (size_t j = 0; j < 4; j++) {
			input_password_vec[i+j]=input_password[j];
		}
	}

	// Make Ciphertext
	Plaintext plaintext;
	for (char ch : input_password_vec) {
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

	encoder.encode(input_password_vec, plaintext);
	Ciphertext encrypted;
	encryptor.encrypt(plaintext, encrypted);

	auto context_data = context.get_context_data(encrypted.parms_id());
	std::cout << "Current level: " << context_data->chain_index() << "\n";

	auto noise_budget = decryptor.invariant_noise_budget(encrypted);
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

	socket_send(encrypted, server_socket);

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
	

	if (is_zero(result_vec)) {
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