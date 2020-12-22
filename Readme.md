Добавил файл source/ak_aes.c, в котором осуществлена реализация шифра AES через интринзики (intel) с маскированием.

Стандарт шифра: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf

Для использования интринзиков используется файл wmmintrin.h

Добавлен пример теста в виде функции bool_t ak_libakrypt_test_aes(). 

В файл libakrypt.h добавлены описания функций bool_t ak_libakrypt_test_aes() и int ak_bckey_create_aes( ak_bckey ) (инициализация секретного ключа) 

