#include "PasswordsEntry.h"
#include "PasswordsEntry.cpp"
/**
 * @file main.cpp
 *
 * @brief Plik główny programu.
 */

/**
 * @brief Główna funkcja programu.
 *
 * Funkcja `main` jest punktem wejściowym programu.
 * Tworzy obiekt `PasswordManager` i wywołuje metodę `run` na tym obiekcie.
 * W przypadku wystąpienia wyjątku, wypisuje komunikat o błędzie na standardowe wyjście błędów.
 *
 * @return Kod zakończenia programu (0 w przypadku sukcesu, 1 w przypadku błędu).
 */

int main() {

    try {
        PasswordManager manager;
        manager.run();
    } catch (const std::exception &e) {
        std::cerr << "Wystąpił wyjątek: " << e.what() << std::endl;
        return 1;
    }



    return 0;

}
