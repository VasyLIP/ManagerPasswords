#include "PasswordsEntry.h"

/**
 * @class PasswordManager
 * @brief Klasa zarządzająca aplikacją Password Manager.
 */

class PasswordManager {
private:
    vector<Password> passwords; /** < Wektor przechowujący wszystkie hasła */
    string sourceFile; /** < Nazwa pliku źródłowego */
    string encryptionKey; /** < Hasło główne do szyfrowania */

    /**
     * @brief Szyfruje dane wejściowe przy użyciu klucza.
     * @param input Dane wejściowe do zaszyfrowania
     * @param key Klucz szyfrowania
     * @return Zaszyfrowane dane
     */
    string encrypt(const string &input, const string &key) {
        string output = input;
        for (char &c : output) {
            c ^= key[0];
        }
        return output;
    }

    /**
     * @brief Deszyfruje zaszyfrowane dane przy użyciu klucza.
     * @param cipherText Zaszyfrowane dane do odszyfrowania
     * @param key Klucz deszyfrowania
     * @return Odszyfrowane dane
     */
    string decrypt(const string &cipherText, const string &key) {
        string output = cipherText;
        for (char &c : output) {
            c ^= key[0];
        }
        return output;
    }

public:
/**
* @brief Uruchamia menedżer haseł
* Główna funkcja uruchamiająca menedżer haseł
* */
void run() {
    cout << "Witaj w aplikacji Password Manager!" << endl;
    /*cout << "Podaj nazwę pliku źródłowego lub ścieżkę do pliku: ";
   cin >> sourceFile;
   cin.ignore();*/
    cout << "Podaj hasło główne do szyfrowania: ";
    cin.ignore();
    cin >> encryptionKey;


    //loadPasswords();

    string command;
    do {
        cout << "\nDostępne komendy:\n"
                  << "1. Wyszukaj hasła\n"
                  << "2. Posortuj hasła\n"
                  << "3. Dodaj hasło\n"
                  << "4. Edytuj hasło\n"
                  << "5. Usuń hasło\n"
                  << "6. Dodaj kategorię\n"
                  << "7. Usuń kategorię\n"
                  << "8. Generuj hasło\n"
                  << "0. Wyjście\n"
                  << "19. Wyswietlienie\n"
                  << "Wybierz komendę: ";
        cin.ignore();
        cin >> command;

        if (command == "1") {
            searchPasswords();
        } else if (command == "2") {
            sortPasswords();
        } else if (command == "3") {
            addPassword();
        } else if (command == "4") {
            editPassword();
        } else if (command == "5") {
            deletePassword();
        } else if (command == "6") {
            addCategory();
        } else if (command == "7") {
            deleteCategory();
        } else if (command == "8") {
            generatePassword();
        }else if(command == "19"){
            showPasswords(passwords);
        } else if (command == "0") {
            savePasswords();
            cout << "Dziękujemy za korzystanie z aplikacji Password Manager!" << endl;
        } else {
            cout << "Nieznana komenda. Spróbuj ponownie." << endl;
        }
    } while (command != "0");
}

private:
    /**
     * @brief Wczytuje hasła z pliku zródłowego.
     *
     * Funkcja odczytuje hasła z pliku żródłowego i zapisuje je do listy hasł.
     * Plik żródłowy powinien być w odpowiednim formacie, gdzie każde hasło
     * jest oddzielone nową linią.
     * */
    void loadPasswords() {
        ifstream inputFile(sourceFile);
        if (inputFile.is_open()) {
            string line;
            while (getline(inputFile, line)) {
                Password password;
                password.password = line;
                passwords.push_back(password);
            }
            inputFile.close();
        } else {
            throw runtime_error("Unable to open source file.");
        }
    }


    /**
 * @brief Zapisuje hasła do pliku zródłowego.
 *
 * Funkcja zapisuje wszystkie hasła z listy do pliku zródłowego.
 * Istniejące dane w pliku zostaną nadpisane.
 * Hasła są zpisywane w zaszyfrowanej postaci, gdzie kazde hasło jest oddzielone noą linią.
 * Jeśli plik zródłowy nie może zosta√ otwarty do zapisu, zostanie wyświetlony odpowiedni komunikat.
 */
    void savePasswords() {
        ofstream file(sourceFile);
        if (!file) {
            cout << "Nie można zapisać do pliku źródłowego." << std::endl;
            return;
        }

        for (const Password& password : passwords) {
            string encryptedLine = encryptPassword(password);
            file << encryptedLine << endl;
        }
    }

    /**
 * @brief Szyfruje podany znacznik czasu.
 *
 * Funkcja szyfruje podany znacznik czasu, przekształcając go na
 * zaszyfrowany ciąg znaków. Szyfrowanie odbywa się poprzez konwersję
 * timestampu na ciąg bajtów, a następnie zastosowanie operacji XOR na każdym bajcie
 * ciąu za pomocą klucza szyfrowania.
 * @param timestamp Znacznik czasu do zaszyfrowania.
 * @return Zaszyfrowany ciąg znaków reprezentujący podany znacznik czasu.
 */
    string encryptTimestamp(time_t timestamp) {
        string encryptedTimestamp;
        for (int i = 0; i < sizeof(timestamp); ++i) {
            encryptedTimestamp.push_back(static_cast<char>((timestamp >> (i * 8)) & 0xFF));
        }
        for (size_t i = 0; i < encryptedTimestamp.size(); ++i) {
            encryptedTimestamp[i] ^= encryptionKey[i % encryptionKey.size()];
        }
        return encryptedTimestamp;
    }


    /**
 * @brieg Szyfruje podane hasło
 * Funkcja szysfruje podane hasło, przekształcając je na zaszyfrowany ciąg znaków.
 * Szyfrowanie odbywa się poprzez:
 * 1. Szyfrowanie danych hasła i zapisywanie ich do zaszyfrowanej linii.
 * 2. Szyfrowanie aktualnego znacznika czasu za pomocą funkcji encrypTimestamp().
 * 3. Mieszanie zaszyfrowanych danych i zaszyfrowanego znacznika czasu.
 *
 * @param password
 * @return Zaszyfrowany ciąg znaków reprezentujący podane hasło.
 */
    string encryptPassword(const Password& password) {
        string encryptedLine;
        string encryptedTimestamp = encryptTimestamp(time(nullptr));
        string mixedLine;
        for (size_t i = 0; i < max(encryptedLine.size(), encryptedTimestamp.size()); ++i) {
            if (i < encryptedLine.size()) {
                mixedLine.push_back(encryptedLine[i]);
            }
            if (i < encryptedTimestamp.size()) {
                mixedLine.push_back(encryptedTimestamp[i]);
            }
        }
        return mixedLine;
    }

    /**
     * @brief Miesza zaszyfrowane hasło i zaszyfrowany znacznik czasu.
     *
     * Funkcja przyjmuje zaszyfrowane hasło  i zaszyfrowany znacznik czasu
     * i łączy je w jedną zaszyfrowaną linię poprzez miesznie ich znaków.
     * Długość wynikowego ziągu jest równa gługości zaszyfrowaego ciąąu.
     * Jeśli jeden z ciąów jest dłuższy, to jego pozostałe znaki są dopisywane
     * na końcu wynikowego ciągu
     * @param encryptedPassword Zaszyfrowane hasło
     * @param encryptedTimestamp Zaszyfrowany znacznik czasu
     * @return Zaszyfrowane ciąg znaków będącym wynikiem mieszania zaszyfrowanego hasła i znacznika czasu.
     */
    string mixLines(const string &encryptedPassword, const string &encryptedTimestamp) {
        string mixed;
        size_t i = 0;
        for (; i < min(encryptedPassword.size(), encryptedTimestamp.size()); ++i) {
            mixed.push_back(encryptedPassword[i]);
            mixed.push_back(encryptedTimestamp[i]);
        }
        for (; i < encryptedPassword.size(); ++i) {
            mixed.push_back(encryptedPassword[i]);
        }
        for (; i < encryptedTimestamp.size(); ++i) {
            mixed.push_back(encryptedTimestamp[i]);
        }
        return mixed;
    }



    /**
 * @brief Deszyfruje zaszyfrowaną linię i zwraca strukturę Password.
 * Funkcja przyjmuje zaszyfrowaną linię zawierającą zaszyfrowane hasło i znacznik czau.
 * i dokonuje deszyfracji tych danych. Następnie przypisuje odszyfrowany znacznik czasu do struktury Password
 * i zwraca tę strukturę.
 *
 * @param mixedLine
 * @return
 */
    Password decryptPassword(const string& mixedLine) {
        Password password;
        string encryptedLine;
        string encryptedTimestamp;
        for (size_t i = 0; i < mixedLine.size(); ++i) {
            if (i % 2 == 0) {
                encryptedLine.push_back(mixedLine[i]);
            } else {
                encryptedTimestamp.push_back(mixedLine[i]);
            }
        }
        time_t timestamp = decryptTimestamp(encryptedTimestamp);
        return password;
    }
    /**
        * @brief Deszyfruje zaszyfrowany znacznik czasu i zwraca wartość typu std::time_t.
        * Funkcja pryjmuje zaszyfrowany znacznik czasu w postaci ciągu bajtów, dokonuje deszyfrowania
        * tego ciągu bajtów za pomocą operacji XOR z użyciem klucza szyfrowania, a następnie konwertuje
        * odszyfrowany ciąg bajtów na wartość typu std::time_t, która reprezentuje znacznik czasu.
        *
        * @param encryptedTimestamp Zaszyfrowany znacznik czasu w postaci ciągu bajtów.
        * @return znacznik czasu w postaci wartosci typu std::time_t.
        */
    time_t decryptTimestamp(const string& encryptedTimestamp) {
        string decryptedTimestamp = encryptedTimestamp;
        for (size_t i = 0; i < decryptedTimestamp.size(); ++i) {
            decryptedTimestamp[i] ^= encryptionKey[i % encryptionKey.size()];
        }
        time_t timestamp = 0;
        for (int i = 0; i < sizeof(timestamp); ++i) {
            timestamp |= (static_cast<time_t>(decryptedTimestamp[i]) << (i * 8));
        }
        return timestamp;
    }

    /**
 * @brief Zapisuje próbę odszyfrowania pliku do logu.
 * Funkcja otwiera plik logu w trybie dopisywania i zapisuje informację
 * wraz z datą i czasem do pliku logu. Następnie zamyka plik logu.
 */
    void logAttempt() {
        ofstream logFile("", ios_base::app);
        if (logFile.is_open()) {
            time_t timestamp = time(nullptr);
            logFile << asctime(localtime(&timestamp)) << " - Próba odszyfrowania pliku" << endl;
            logFile.close();
        }
    }

    /**
 * @brief Wyszukuje hasła na podstawie podanej frazy.
 * Funkcja prosi użytkownika o podanie szukanej frazy, a następnie przeszukuje
 * przechowywne hasła w poszukiwaniu dopasowań. Hasła są porównywanez podaną frazą
 * na podstawie nazwy, kategori, adresu strony internetowej oraz loginu.
 * Znalezione hasła są wyświetlane na ekranie.
 * Jeśli żadne pasujące hasła nie zostaną znalezione, wypisywany jest odpowiedni komunikat.
 */
    void searchPasswords() {
        string searchTerm;
        cout << "Podaj szukaną frazę: ";
        cin.ignore();
        getline(cin, searchTerm);
        vector<Password> matchingPasswords;
        for (const Password& password : passwords) {
            if (password.name.find(searchTerm) != string::npos ||
                password.category.find(searchTerm) != string::npos ||
                password.website->find(searchTerm) != string::npos ||
                password.login->find(searchTerm) != string::npos) {
                matchingPasswords.push_back(password);
            }
        }
        if (matchingPasswords.empty()) {
            cout << "Nie znaleziono pasujących haseł." << endl;
        } else {
            cout << "Znalezione hasła:" << endl;
            displayPasswords(matchingPasswords);
        }
    }


    /**
 * @brief Generuje losowe hasło na podstawie podanych paramatrów.
 * Funkcja prosi użytkownika o podanie długości hasła oraz informacji o tym, jakie
 * elementy powinny być zawarte w haśle (symbole, cyfry, małe litery, duże litery).
 * Na podstawie podanych paramatrów genetuje się losowe hasło i zwraca sięje jako wynik.
 *
 * @return Wygenerowane losowe hasło.
 */
    string generatePassword() {
        int length;
        bool includeSymbols, includeNumbers, includeLowercase, includeUppercase;
        cout << "Podaj długość hasła: ";
        cin >> length;
        cout << "Czy hasło ma zawierać symbole (1 - tak, 0 - nie)? ";
        cin >> includeSymbols;
        cout << "Czy hasło ma zawierać cyfry (1 - tak, 0 - nie)? ";
        cin >> includeNumbers;
        cout << "Czy hasło ma zawierać małe litery (1 - tak, 0 - nie)? ";
        cin >> includeLowercase;
        cout << "Czy hasło ma zawierać duże litery (1 - tak, 0 - nie)? ";
        cin >> includeUppercase;
        string symbols = "!@#$%^&*()";
        string numbers = "0123456789";
        string lowercase = "abcdefghijklmnopqrstuvwxyz";
        string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        string characters;
        if (includeSymbols) {
            characters += symbols;
        }
        if (includeNumbers) {
            characters += numbers;
        }
        if (includeLowercase) {
            characters += lowercase;
        }
        if (includeUppercase) {
            characters += uppercase;
        }
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(0, characters.size() - 1);

        string password;
        for (int i = 0; i < length; i++) {
            password += characters[dis(gen)];
        }
        return password;
    }

    void showPasswords(const vector<Password>& pass){
        for(auto password : pass){
            cout << "Name " << password.name;
            cout << "Kategory " << password.category;
            cout << "Password " << password.password;
            if(password.login.has_value()){
                cout << "Login " << password.login.value();
            }
            if(password.website.has_value()){
                cout << "Website " << password.website.value();
            }
        }
    }

    /**
 * @brief Zapisuje hasło do pliku w postaci zaszyfrowanej.
 * Funkcja zapisuje podane hasło do pliku o podanej ścieżce. Haslo jest zapisywane w
 * postaci zaszyfrowanej przy użyciu podanego klucza. Zapisywane są również i inne dane
 * związane z hasłem, takie jak nazwa, kategoria, strona internetowa i login.
 * Dodatkowo, do pliku zapisywany jest również timestamp w zaszyfrowanej postaci.
 * W przypadku wystąpienia błędu podczas zapisu do pliku, wypisywany jest odpowiedni komunikat.
 *
 * @param password Hasło do zapisywania.
 * @param filePath Ścieżka do pliku, do którego ma być zapisane hasło.
 * @param key Klucz yżywany do zaszyfrowania danych.
 */
    void writePasswordToFile(const Password& password, const string& sourceFile, const string& key) {
        try {
            ofstream file(sourceFile);
            if (!file) {
                throw runtime_error("Nie można otworzyć pliku do zapisu");
            }
            file << encrypt(password.name, key) << endl;
            file << encrypt(password.password, key) << endl;
            file << encrypt(password.category, key) << endl;
            if (password.website.has_value()) {
                file << encrypt(*password.website, key) << endl;
            }
            if (password.login.has_value()) {
                file << encrypt(*password.login, key) << endl;
            }
            time_t timestamp = time(nullptr);
            tm* timeinfo = localtime(&timestamp);
            for (int i = 1; i <= 33; ++i) {
                if (i == 11) {
                    file << setfill('0') << setw(2) << timeinfo->tm_hour << encrypt("DDDD", key) << endl;
                } else if (i == 22) {
                    file << setfill('0') << setw(2) << timeinfo->tm_min << encrypt("DDDD", key) << endl;
                } else if (i == 33) {
                    file << setfill('0') << setw(2) << timeinfo->tm_sec << encrypt("DDDD", key) << endl;
                } else {
                    file << endl;
                }
            }
            file.close();
        } catch (const exception& e) {
            cerr << "Wystąpił wyjątek: " << e.what() << endl;
        }
    }





    void sortPasswords() {
        string sortBy;
        cout << "Podaj parametr sortowania (name, category, website, login): ";
        cin >> sortBy;

        vector<Password> sortedPasswords = passwords;

        if (sortBy == "name") {
            sort(sortedPasswords.begin(), sortedPasswords.end(),
                 [](const Password& a, const Password& b) {
                     return a.name < b.name;
                 });
        } else if (sortBy == "category") {
            sort(sortedPasswords.begin(), sortedPasswords.end(),
                 [](const Password& a, const Password& b) {
                     return a.category < b.category;
                 });
        } else if (sortBy == "website") {
            sort(sortedPasswords.begin(), sortedPasswords.end(),
                 [](const Password& a, const Password& b) {
                     return a.website < b.website;
                 });
        } else if (sortBy == "login") {
            sort(sortedPasswords.begin(), sortedPasswords.end(),
                 [](const Password& a, const Password& b) {
                     return a.login < b.login;
                 });
        } else {
            cout << "Nieznany parametr sortowania." << endl;
            return;
        }

        cout << "Posortowane hasła:" << endl;
        displayPasswords(sortedPasswords);
    }


    void addPassword() {
        std::cin.ignore();
        std::string name, password, category, website, login;

        std::cout << "Enter name: ";
        std::getline(std::cin, name);
        std::cout << "Enter password: ";
        std::getline(std::cin, password);
        std::cout << "Enter category: ";
        std::getline(std::cin, category);
        std::cout << "Enter website: ";
        std::getline(std::cin, website);
        std::cout << "Enter login: ";
        std::getline(std::cin, login);

        Password newPassword = {name, password, category, website, login};
        passwords.push_back(newPassword);

        std::ofstream outfile(sourceFile, std::ios_base::app);
        if (outfile.is_open()) {
            outfile << name << ',' << password << ',' << category << ',' << website << ',' << login << '\n';
            std::cout << "Password added successfully!\n";
        } else {
            std::cerr << "Failed to open the file.\n";
        }
    }


    /**
 * @brief Sortuje przechowywane hasła na podstawie podanego parametru.
 *
 * Funkcja prosi użytkownika o podanie parametru sortowania (name, category, website, login)
 * i sortuje przechowywane hasła na podstawie tego parametru. Posortowane hasła są wyświetlane na ekranie.
 * Jeśli podany parametr sortowania jest nieznany, wypisywany jest odpowiedni komunikat.
 */

    void editPassword() {
        string name;
        cout << "Podaj nazwę hasła do edycji: ";
        cin.ignore();
        getline(cin, name);

        auto it = find_if(passwords.begin(), passwords.end(),
                               [&name](const Password& password) {
                                   return password.name == name;
                               });

        if (it != passwords.end()) {
            Password& password = *it;

            cout << "Podaj nową nazwę hasła: ";
            getline(cin, password.name);

            cout << "Podaj nowy tekst hasła: ";
            getline(cin, password.password);

            cout << "Podaj nową kategorię: ";
            getline(cin, password.category);

            string website;
            cout << "Podaj nową stronę internetową/serwis: ";
            getline(cin, website);
            password.website = website;

            string login;
            cout << "Podaj nowy login: ";
            getline(cin, login);
            password.login = login;

            cout << "Hasło zostało zaktualizowane." << endl;
        } else {
            cout << "Nie znaleziono hasła o podanej nazwie." << endl;
        }
    }
/**
 * @brief Usuwa hasło na podstawie podanej nazwy.
 *
 * Funkcja prosi użytkownika o podanie nazwy hasła do usunięcia.
 * Następnie wyszukuje hasło o podanej nazwie w przechowywanej kolekcji haseł i je usuwa.
 * Jeśli hasło zostanie znalezione i usunięte, wypisywany jest odpowiedni komunikat.
 * Jeśli nie zostanie znalezione hasło o podanej nazwie, wypisywany jest odpowiedni komunikat.
 */
    void deletePassword() {
        string name;
        cout << "Podaj nazwę hasła do usunięcia: ";
        cin.ignore();
        getline(cin, name);

        auto it = remove_if(passwords.begin(), passwords.end(),
                                 [&name](const Password& password) {
                                     return password.name == name;
                                 });

        if (it != passwords.end()) {
            passwords.erase(it, passwords.end());
            cout << "Hasło zostało usunięte." << endl;
        } else {
            cout << "Nie znaleziono hasła o podanej nazwie." << endl;
        }
    }
/**
 * @brief Dodaje nową kategorię do istniejących haseł.
 *
 * Funkcja prosi użytkownika o podanie nazwy nowej kategorii.
 * Następnie dodaje tę kategorię do wszystkich istniejących haseł w kolekcji.
 * Po dodaniu kategorii, wypisywany jest odpowiedni komunikat potwierdzający.
 */
    void addCategory() {
        string newCategory;
        cout << "Podaj nazwę nowej kategorii: ";
        cin.ignore();
        getline(cin, newCategory);

        for (Password& password : passwords) {
            password.category = newCategory;
        }

        cout << "Kategoria została dodana do wszystkich haseł." << endl;
    }

    /**
 * @brief Usuwa daną kategorię z istniejących haseł.
 *
 * Funkcja prosi użytkownika o podanie nazwy kategorii do usunięcia.
 * Następnie usuwa tę kategorię ze wszystkich istniejących haseł w kolekcji.
 * Po usunięciu kategorii, wypisywany jest odpowiedni komunikat potwierdzający.
 */
    void deleteCategory() {
        string categoryToDelete;
        cout << "Podaj nazwę kategorii do usunięcia: ";
        cin.ignore();
        getline(cin, categoryToDelete);

        for (Password& password : passwords) {
            if (password.category == categoryToDelete) {
                password.category = "";  // lub jakaś domyślna wartość
            }
        }

        cout << "Kategoria została usunięta z wszystkich odpowiednich haseł." << endl;
    }

    /**
 * @brief Wyświetla listę haseł.
 *
 * Funkcja wyświetla informacje o każdym haśle z listy haseł.
 * Dla każdego hasła wyświetlane są jego nazwa, hasło, kategoria,
 * oraz opcjonalnie strona internetowa/serwis i login.
 *
 * @param passwordList Lista haseł do wyświetlenia.
 */
    void displayPasswords(const vector<Password>& passwordList) {
        for (const Password& password : passwordList) {
            cout << "Nazwa: " << password.name << endl;
            cout << "Hasło: " << password.password << endl;
            cout << "Kategoria: " << password.category << endl;
            if (password.website.has_value()) {
                cout << "Strona internetowa/serwis: " << *password.website << endl;
            }
            if (password.login.has_value()) {
                cout << "Login: " << *password.login << endl;
            }
            cout << endl;
        }
    }



};
