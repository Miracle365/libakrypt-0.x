#include <libakrypt-internal.h>
#include <limits.h>
#include <stdint.h>     //for int8_t
#include <string.h>     //for memcmp
#include <wmmintrin.h>  //for intrinsics for AES-NI
#include <stdio.h>

//uint8_t = byte
//uint32_t = word = 4*byte = 32 bits;

// Развертка ключа (определения функций и структур, использующихся в процессе)
//--------------------------------------------------------------------------------------------------------------------------------------

ak_uint32 RotWord(ak_uint32 w){ //Функция перестановки
    ak_uint32 c = (w & 0x00FF0000) >> 16;

    ak_uint32 tool = 0x0000FF00;
    c = (c << 8) + ((w & tool) >> 8);
    //tool = 0xFFFF000000000000;

    tool = 0x000000FF;
    c = (c << 8) + (w & tool);

    c = (c << 8) + ((w & 0xFF000000) >> 24);
    return c;
}

typedef __m128i ak_aes_expanded[20];

ak_uint8 Sbox[16][16] = {{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
                        {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
                        {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
                        {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
                        {0x09, 0x83, 0x2c, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
                        {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
                        {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
                        {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
                        {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
                        {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
                        {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                        {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
                        {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
                        {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
                        {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
                        {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};

ak_uint32 SubWord(ak_uint32 w){ //Функция подстановки - заменяем значения в массиве на значения из матрицы SBox
    ak_uint32 c = (w >> 24); //берем первое слово
    ak_uint8 b = (ak_uint8)c;
    ak_uint8 x = b >> 4; //старшая часть байта b
    ak_uint8 tool = 0x0F;
    ak_uint8 y = b & tool; //младшая часть байта b
    b = Sbox[x][y];

    //Аналогично для других слов
    ak_uint32 res = b;

    c = (w << 8);
    c = (c >> 24);
    b = (ak_uint8)c;
    x = b >> 4; //старшая часть байта b
    y = b & tool; //младшая часть байта b
    b = Sbox[x][y];

    res = (res << 8) + b;

    c = (w << 16);
    c = (c >> 24);
    b = (uint8_t)c;
    x = b >> 4; //старшая часть байта b
    y = b & tool; //младшая часть байта b
    b = Sbox[x][y];

    res = (res << 8) + b;

    c = (w << 24);
    c = (c >> 24);
    b = (ak_uint8)c;
    x = b >> 4; //старшая часть байта b
    y = b & tool; //младшая часть байта b
    b = Sbox[x][y];

    res = (res << 8) + b;

    return res;
}

ak_uint32 Rcon[10];

void ak_RconZap(){                                  //заполнение массива Rcon[] значениями, взятыми из стандарта (значения многочлена х в поле Галуа)
    Rcon[0] = 0x01000000;
    Rcon[1] = 0x02000000;
    Rcon[2] = 0x04000000;
    Rcon[3] = 0x08000000;
    Rcon[4] = 0x10000000;
    Rcon[5] = 0x20000000;
    Rcon[6] = 0x40000000;
    Rcon[7] = 0x80000000;
    Rcon[8] = 0x1b000000;
    Rcon[9] = 0x36000000;
}

void ak_convert(ak_uint8 block[], ak_uint32 mas[]){ //ak_uint32[4] -> ak_uint8[16]
    int i = 4;
    for(int k = 0; k < 4; k++){
        block[k * i] = (ak_uint8) (mas[k] >> 24);
        block[k * i + 1] = (ak_uint8) ((mas[k] << 8) >> 24);
        block[k * i + 2] = (ak_uint8) ((mas[k] << 16) >> 24);
        block[k * i + 3] = (ak_uint8) ((mas[k] << 24) >> 24);
    }
}

//Функция развертки ключей + генерация раундовых ключей дляобратного шифрования с использованием _mm_aesimc_si128
void ak_key_expansion(ak_uint8 key[16], __m128i key_exp[]){
    ak_RconZap();
    ak_uint32 w[44] = {0}; //w[0] :: w[3] = key
    ak_uint32 temp;
    int i = 0;
    w[i] = key[0];
    while (i < 4){
        w[i] = key[4*i];
        w[i] = (w[i] << 8) + key[4*i + 1];
        w[i] = (w[i] << 8) + key[4*i + 2];
        w[i] = (w[i] << 8) + key[4*i + 3]; //приведение байтов к слову
        i = i + 1;
    }
    i = 4;                 //w[4] :: w[44] = Round keys
    while(i < 4*11){       //4 слова - длина ключа, 11 ключей используется при шифровании
        temp = w[i - 1];
        if(i % 4 == 0){
            temp = SubWord(RotWord(temp)) ^ Rcon[i/4 - 1];
        }
        w[i] = w[i - 4] ^ temp; //XOR
        i = i + 1;
    }

    ak_uint8 block[16];

    ak_uint32 ww[4];
    for(int k = 0; k < 11; k++){
        for(int i = k * 4; i < k * 4 + 4; i++){
            ww[i - k*4] = w[i];
        }                                               //каждые 4 слова (ключ) конвертируем в 16 подряд идущих байт
        ak_convert(block, ww);                          //для их последующего преобразования в элемент массива __m128i[20]
        key_exp[k] = _mm_loadu_si128((__m128i*) block); //Теперь в key_exp содержится 11 наборов ключей длиной 128 бит каждый
    }

    // генерируем ключи для дешифрования (алгоритм Equivalent Inverse cipher)
    key_exp[11] = _mm_aesimc_si128(key_exp[9]);         //функция выполняет преобразование InvMixColumns над ключами
    key_exp[12] = _mm_aesimc_si128(key_exp[8]);
    key_exp[13] = _mm_aesimc_si128(key_exp[7]);
    key_exp[14] = _mm_aesimc_si128(key_exp[6]);
    key_exp[15] = _mm_aesimc_si128(key_exp[5]);
    key_exp[16] = _mm_aesimc_si128(key_exp[4]);
    key_exp[17] = _mm_aesimc_si128(key_exp[3]);
    key_exp[18] = _mm_aesimc_si128(key_exp[2]);
    key_exp[19] = _mm_aesimc_si128(key_exp[1]);
}



void ak_aes128_enc(__m128i *key_schedule, ak_uint8 *plainText, ak_uint8 *cipherText){
    __m128i m = _mm_loadu_si128((__m128i *) plainText); //помещаем первые 128 бит массива plainText в m

    m = _mm_xor_si128       (m, key_schedule[ 0]);

    m = _mm_aesenc_si128    (m, key_schedule[ 1]); //раунды
    m = _mm_aesenc_si128    (m, key_schedule[ 2]);
    m = _mm_aesenc_si128    (m, key_schedule[ 3]);
    m = _mm_aesenc_si128    (m, key_schedule[ 4]);
    m = _mm_aesenc_si128    (m, key_schedule[ 5]);
    m = _mm_aesenc_si128    (m, key_schedule[ 6]);
    m = _mm_aesenc_si128    (m, key_schedule[ 7]);
    m = _mm_aesenc_si128    (m, key_schedule[ 8]);
    m = _mm_aesenc_si128    (m, key_schedule[ 9]);
    m = _mm_aesenclast_si128(m, key_schedule[10]);

    _mm_storeu_si128((__m128i *) cipherText, m); //Получившиеся 128 бит помещаем в массив cipherText
}

void ak_aes128_dec(__m128i *key_schedule, ak_uint8 *cipherText, ak_uint8 *plainText){
    __m128i m = _mm_loadu_si128((__m128i *) cipherText);

    m = _mm_xor_si128       (m, key_schedule[10+0]);

    m = _mm_aesdec_si128    (m, key_schedule[10+1]); //раунды
    m = _mm_aesdec_si128    (m, key_schedule[10+2]);
    m = _mm_aesdec_si128    (m, key_schedule[10+3]);
    m = _mm_aesdec_si128    (m, key_schedule[10+4]);
    m = _mm_aesdec_si128    (m, key_schedule[10+5]);
    m = _mm_aesdec_si128    (m, key_schedule[10+6]);
    m = _mm_aesdec_si128    (m, key_schedule[10+7]);
    m = _mm_aesdec_si128    (m, key_schedule[10+8]);
    m = _mm_aesdec_si128    (m, key_schedule[10+9]);
    m = _mm_aesdeclast_si128(m, key_schedule[0]);

    _mm_storeu_si128((__m128i *) plainText, m);
}

//Функции приводят данные к типу_m128i * и запускают соответственно алгоритмы шифрования и дешифрования
static void ak_aes_encrypt(ak_skey skey, ak_pointer in, ak_pointer out){
    ak_uint8 * plain = (ak_uint8 *)  in;
    __m128i * enc_key =  (__m128i * ) skey->data;
    ak_uint8 * cipher = (ak_uint8 *) out;
    ak_aes128_enc(enc_key, plain, cipher);
}

static void ak_aes_decrypt(ak_skey skey, ak_pointer in, ak_pointer out){
    ak_uint8 * cipher = (ak_uint8 *)  in;
    __m128i * enc_key =  (__m128i * ) skey->data;
    ak_uint8 * plain = (ak_uint8 *) out;
    ak_aes128_dec(enc_key, cipher, plain);
}

//Функция освобождает память, занимаемую развернутыми ключами
static int ak_aes_delete_keys(ak_skey skey){
    int error = ak_error_ok;

     /* выполняем стандартные проверки */
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                     __func__ , "using a null pointer to secret key" );
    if( skey->data != NULL ) {
         /* теперь очистка и освобождение памяти */
        if(( error = ak_ptr_wipe( skey->data, sizeof( ak_aes_expanded ),
                                                                   &skey->generator )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect wiping an internal data" );
        memset( skey->data, 0, sizeof( ak_aes_expanded ));
        }
        free( skey->data );
        skey->data = NULL;
    }
    return error;
}

// функция маскирования, которая ничего не делает (реализация без маскирования)
int ak_skey_aes_mask(ak_skey skey){
    /*if((( skey->flags)&ak_key_flag_set_mask ) == 0 ) {
        skey->flags |= ak_key_flag_set_mask;
    }*/
    return ak_error_ok;
}

int ak_skey_aes_unmask(ak_skey skey){
    /*if( (( skey->flags)&ak_key_flag_set_mask ) == 0 ) {
        return ak_error_ok;
    }
    skey->flags ^= ak_key_flag_set_mask;*/
    return ak_error_ok;
}

static int ak_aes_schedule_keys(ak_skey skey){
    /* выполняем стандартные проверки */
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
    if( skey->key_size != 16 ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                              "unsupported length of secret key" );
    /* проверяем целостность ключа */
    if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                __func__ , "using key with wrong integrity code" );
    /* удаляем былое */
    if( skey->data != NULL ) ak_aes_delete_keys( skey );

    /* далее, по-возможности, выделяем выравненную память */
    if(( skey->data = ak_aligned_malloc( sizeof( ak_aes_expanded ))) == NULL )
        return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                             "wrong allocation of internal data" );

    __m128i * enc_key = (__m128i *) skey->data; //Поскольку шифрование происходит через интринзики, ключи удобнее хранить с типом __m128i
    ak_key_expansion(skey->key, enc_key); //После выполнения enc_key указывает на начало массива _m128i[20], содержащего раундовые ключи для шифрования и дешифрования

    return ak_error_ok;
}

int ak_bckey_create_aes(ak_bckey bkey){
    int error = ak_error_ok;

     if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to block cipher key context" );

    /* инициализируем параметры: ключ и методы, задействованные в шифровании */
    if(( error = ak_bckey_create( bkey, 16, 16 )) != ak_error_ok )
        return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );

    bkey->schedule_keys = ak_aes_schedule_keys;
    bkey->delete_keys = ak_aes_delete_keys;
    bkey->encrypt = ak_aes_encrypt;
    bkey->decrypt = ak_aes_decrypt;
    bkey->key.set_mask = ak_skey_aes_mask;   // заменим функции маскирования и демаскирования по умолчанию
    bkey->key.unmask = ak_skey_aes_unmask;   // поскольку в текущей реализации маскирование не предусмотрено
    return error;
}
