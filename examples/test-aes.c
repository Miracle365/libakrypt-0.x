#include <stdio.h>
#include <libakrypt.h>
#include <wmmintrin.h>

void print128_num(__m128i var) //Для вывода раундового ключа
{
    ak_uint8 val[16];
    memcpy(val, &var, sizeof(val));
    printf("Hexademical: %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X \n",
           val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
           val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15]);
}

int main()
{   ak_uint8 plain[16] ={0x39,0x25,0x84,0x1d,0x02,0xDC,0x09,0xFB,0xDC,0x11,0x85,0x97,0x19,0x6A,0x0B,0x32};
    ak_uint8 key[16] = {0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C};

    ak_uint8 cipher[16];
    ak_uint8 plain_dec[16];

    struct bckey Bigkey;


    if (ak_bckey_create_aes(&Bigkey) != ak_error_ok) {
        printf("Проблема в ak_bckey_create_aes\n");
        return -1;
    }

    if (ak_bckey_set_key(&Bigkey, key, 16) != ak_error_ok){
        printf("Проблема в ak_bckey_set_key\n");
        return -1;
    }


    __m128i * expand = Bigkey.key.data;
    printf("Развертка ключа:\n");
    for(int i = 0; i < 20; i++){
        print128_num((__m128i) expand[i]);
    }
    if (ak_bckey_encrypt_ecb(&Bigkey, plain, cipher, 16 ) != ak_error_ok) {
        printf("Проблема в ak_bckey_encrypt_ecb\n");
        return -1;
    }



    printf("\nПроцедура шифрования\nОткрытый текст: ");
    for (int i = 0; i < 16; i++){
        printf("%X ", plain[i]);
    }
    printf("\nКлюч: ");
    for (int i = 0; i < 16; i++){
        printf("%X ", key[i]);
    }
    printf("\nШифртекст: ");
    for (int i = 0; i < 16; i++){
        printf("%X ", cipher[i]);
    }




    if (ak_bckey_set_key(&Bigkey, key, 16) != ak_error_ok){
        printf("Проблема в ak_bckey_set_key\n");
        return -1;
    }

    if (ak_bckey_decrypt_ecb(&Bigkey, cipher, plain_dec, 16 ) != ak_error_ok) {
        printf("Проблема в ak_bckey_decrypt_ecb\n");
        return -1;
    }
    printf("\n\nПроцедура дешифрования:\nШифр: ");
    for (int i = 0; i < 16; i++){
        printf("%X ", cipher[i]);
    }
    printf("\nКлюч: ");
    for (int i = 0; i < 16; i++){
        printf("%X ", key[i]);
    }
    printf("\nРезультат: ");
    for (int i = 0; i < 16; i++){
        printf("%X ", plain_dec[i]);
    }
    return 0;
}
