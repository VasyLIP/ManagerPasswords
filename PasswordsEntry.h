#ifndef INC_2223L_16C_S26875_PASSWORDSENTRY_H
#define INC_2223L_16C_S26875_PASSWORDSENTRY_H

#include <algorithm>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <string>
#include <vector>
#include <cstring>
#include <cerrno>


using namespace std;
/**
 * @file PasswordsEntry.h
 *
 * @brief Plik nagłówkowy zawierający deklarację struktury Password oraz dyrektywę include dla bibliotek standardowych.
 */

/**
 * @struct Password
 *
 * @brief Struktura reprezentująca pojedyncze hasło.
 *
 * Struktura zawiera pola name, password, category, website i login,
 * które przechowują odpowiednie informacje dotyczące hasła.
 */
struct Password {
    string name;   /**< Nazwa hasła */
    string password;   /**< Hasło */
    string category;   /**< Kategoria */
    optional<std::string> website; /**< Strona internetowa/serwis */
    optional<std::string> login;   /**< Login */
};
#endif
