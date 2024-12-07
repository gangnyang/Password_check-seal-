#include "SEALtest.h"
#include <omp.h>
#include <winsock.h>
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#pragma comment(lib, "ws2_32.lib")
#define PACKET 16384

inline void socket_receive(Ciphertext& received_pw, SEALContext& context, SOCKET socket) {
	vector<char> data;
	char buffer[PACKET] = { 0 };
	size_t data_length;
	int bytes_received = recv(socket, reinterpret_cast<char*>(&data_length), sizeof(data_length), 0);

	size_t total_received = 0;
	while (total_received < data_length) {
		bytes_received = recv(socket, buffer, PACKET, 0);
		string received_data(buffer, bytes_received);
		data.insert(data.end(), buffer, buffer + bytes_received);
		total_received += bytes_received;
		cout << "Received " << total_received << "\n";
	}
	cout << "Received all data\n";
	stringstream stream;
	stream.write(data.data(), data.size());

	try {
		received_pw.load(context, stream);
		cout << "Ciphertext receive... Complete.\n";
	}
	catch (const exception& e) {
		cerr << "Failed to load Ciphertext: " << e.what() << "\n";
	}
}

inline void socket_send(string message, SOCKET socket) {
	// 클라이언트로 메세지 전송
	int bytes_sent = send(socket, message.c_str(), message.length(), 0);

	if (bytes_sent == SOCKET_ERROR) {
		cerr << "Send failed.\n";
	}
	else {
		cout << "Sent Successfully.\n";
	}
}

inline void socket_send(Ciphertext& message, SOCKET socket) {
	// 클라이언트로 암호화된 메세지 전송
	cout << "Ciphertext Sending...\n";
	stringstream stream;
	message.save(stream);
	string serialized = stream.str();
	size_t data_length = serialized.size();
	send(socket, reinterpret_cast<char*>(&data_length), sizeof(data_length), 0);
	cout << "Data_size: " << data_length << "\n";
	size_t total_sent = 0;

	while (total_sent < data_length) {
		size_t remain = data_length - total_sent;
		size_t packet_size = min(PACKET, remain);

		send(socket, serialized.c_str() + total_sent, packet_size, 0);
		total_sent += packet_size;
		cout << "Sending " << total_sent << "/" << data_length << "\n";
	}
}