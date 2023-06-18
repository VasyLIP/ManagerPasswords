cmake_minimum_required(VERSION 3.25)
project(2223L_16c_s26875)

set(CMAKE_CXX_STANDARD 17)

# Pliki źródłowe do projektu
set(SOURCES
        main.cpp
        PasswordsEntry.cpp
        PasswordsEntry.h
        )

# Plik nagłówkowy do projektu
set(HEADERS
        PasswordsEntry.h
        )

# Wykonywalny plik projektu
add_executable(PasswordManager ${SOURCES})


