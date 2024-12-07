// Test multiplying minus
#include <examples.h>
#define SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT OFF

using namespace std;
using namespace seal;

void main()
{
	print_example_banner("Leaked Password Test");

	EncryptionParameters params(scheme_type::bgv);
	size_t poly_modulus_degree = 8192;
	params.set_poly_modulus_degree(poly_modulus_degree);
	params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

	SEALContext context(params);
	print_line(__LINE__);
	print_parameters(context);
	
	KeyGenerator keygen(context);
	SecretKey sk = keygen.secret_key();
	PublicKey pk;
	RelinKeys rk;
	keygen.create_public_key(pk);
	keygen.create_relin_keys(rk);
	Encryptor encryptor(context, pk);
	Decryptor decryptor(context, sk);
	Evaluator evaluator(context);

	BatchEncoder encoder(context);
	size_t slot_count = encoder.slot_count();
	size_t row_size = slot_count / 2;

	vector<uint64_t> prod_matrix(slot_count, 0ULL);
	prod_matrix[1] = 1ULL;
	prod_matrix[2] = 2ULL;
	prod_matrix[3] = 3ULL;
	prod_matrix[4] = 8ULL;
	print_matrix(prod_matrix, row_size);

	Plaintext plain_matrix;
	encoder.encode(prod_matrix, plain_matrix);

	vector<uint64_t> temp_result;
	encoder.decode(plain_matrix, temp_result);
	print_matrix(temp_result, row_size);

	Ciphertext x_encrypted1, x_encrypted2;
	print_line(__LINE__);
	encryptor.encrypt(plain_matrix, x_encrypted1);
	encryptor.encrypt(plain_matrix, x_encrypted2);
	cout << "Noise budget of x_encrypted1: " << decryptor.invariant_noise_budget(x_encrypted1) << '\n';
	cout << "Noise budget of x_encrypted2: " << decryptor.invariant_noise_budget(x_encrypted2) << "\n";

	
	Ciphertext Cipher_result;
	evaluator.negate_inplace(x_encrypted2);

	evaluator.add(x_encrypted1, x_encrypted2, Cipher_result);

	Plaintext plain_result;
	decryptor.decrypt(Cipher_result, plain_result);
	vector <uint64_t> result;
	encoder.decode(plain_result, result);
	print_line(__LINE__);
	print_matrix(result, row_size);
}

// OK 기존 코드에서는 이미 암호화된 Ciphertext를 복제해서 사용했기 때문에 빼기 연산 후 아예 암호문이 사라져버림.
// 같은 행렬로 두 개의 암호문을 만들면 deterministic하지 않기 때문에 빼기 연산 후 복호화하면 정상적으로 0이 출력되는 모습을 볼 수 있다.