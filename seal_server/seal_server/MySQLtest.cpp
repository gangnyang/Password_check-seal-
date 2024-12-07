#include <jdbc/mysql_driver.h>
#include <jdbc/mysql_connection.h>
#include <iostream>

int main() {
    try {
        sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> con(driver->connect("tcp://localhost:3306", "root", "sang8429"));
        con->setSchema("crypto");
        std::cout << "MySQL ���� ����!" << std::endl;
    }
    catch (sql::SQLException& e) {
        std::cerr << "MySQL ���� ����: " << e.what() << std::endl;
    }

    return 0;
}