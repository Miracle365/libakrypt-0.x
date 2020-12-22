#ifndef __AES_NI_H__
#define __AES_NI_H__

#include <stdint.h>     //for int8_t
#include <string.h>     //for memcmp
#include <wmmintrin.h>  //for intrinsics for AES-NI
#include <libakrypt-internal.h>
#include <stdio.h>

//compile using gcc and following arguments: -g;-O0;-Wall;-msse2;-msse;-march=native;-maes

//макрос, где проводятся 10 раундов шифрования через интринзики
#define DO_ENC_BLOCK(m,k) \ 
    do{\ 
        m = _mm_xor_si128       (m, k[ 0]); \
        m = _mm_aesenc_si128    (m, k[ 1]); \
        m = _mm_aesenc_si128    (m, k[ 2]); \
        m = _mm_aesenc_si128    (m, k[ 3]); \
        m = _mm_aesenc_si128    (m, k[ 4]); \
        m = _mm_aesenc_si128    (m, k[ 5]); \
        m = _mm_aesenc_si128    (m, k[ 6]); \
        m = _mm_aesenc_si128    (m, k[ 7]); \
        m = _mm_aesenc_si128    (m, k[ 8]); \
        m = _mm_aesenc_si128    (m, k[ 9]); \
        m = _mm_aesenclast_si128(m, k[10]);\
    }while(0)

//макрос, где проводятся 10 раундов дешифрования через интринзики
#define DO_DEC_BLOCK(m,k) \
    do{\
        m = _mm_xor_si128       (m, k[10+0]); \
        m = _mm_aesdec_si128    (m, k[10+1]); \
        m = _mm_aesdec_si128    (m, k[10+2]); \
        m = _mm_aesdec_si128    (m, k[10+3]); \
        m = _mm_aesdec_si128    (m, k[10+4]); \
        m = _mm_aesdec_si128    (m, k[10+5]); \
        m = _mm_aesdec_si128    (m, k[10+6]); \
        m = _mm_aesdec_si128    (m, k[10+7]); \
        m = _mm_aesdec_si128    (m, k[10+8]); \
        m = _mm_aesdec_si128    (m, k[10+9]); \
        m = _mm_aesdeclast_si128(m, k[0]);\
    }while(0)

#define AES_128_key_exp(k, rcon) ak_aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))
//макрос для расширения ключа

typedef ak_uint8 ak_aes_key[20];

static __m128i ak_aes_128_key_expansion(__m128i key, __m128i keygened){ //расширение ключа (выработка новых)
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3)); //смещение байтов
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

static void ak_aes128_load_key_enc_only(ak_uint8 *enc_key, __m128i *key_schedule){
    key_schedule[0] = _mm_loadu_si128((const __m128i*) enc_key);
    key_schedule[1]  = AES_128_key_exp(key_schedule[0], 0x01);
    key_schedule[2]  = AES_128_key_exp(key_schedule[1], 0x02);
    key_schedule[3]  = AES_128_key_exp(key_schedule[2], 0x04);
    key_schedule[4]  = AES_128_key_exp(key_schedule[3], 0x08);
    key_schedule[5]  = AES_128_key_exp(key_schedule[4], 0x10);
    key_schedule[6]  = AES_128_key_exp(key_schedule[5], 0x20);
    key_schedule[7]  = AES_128_key_exp(key_schedule[6], 0x40);
    key_schedule[8]  = AES_128_key_exp(key_schedule[7], 0x80);
    key_schedule[9]  = AES_128_key_exp(key_schedule[8], 0x1B);
    key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);
}

static void ak_aes128_load_key(ak_uint8 *enc_key, __m128i *key_schedule){
    ak_aes128_load_key_enc_only(enc_key, key_schedule);

    // генерация ключей шифрования
    // k[0] содержит оригинальный (пользовательский) ключ
    key_schedule[11] = _mm_aesimc_si128(key_schedule[9]);
    key_schedule[12] = _mm_aesimc_si128(key_schedule[8]);
    key_schedule[13] = _mm_aesimc_si128(key_schedule[7]);
    key_schedule[14] = _mm_aesimc_si128(key_schedule[6]);
    key_schedule[15] = _mm_aesimc_si128(key_schedule[5]);
    key_schedule[16] = _mm_aesimc_si128(key_schedule[4]);
    key_schedule[17] = _mm_aesimc_si128(key_schedule[3]);
    key_schedule[18] = _mm_aesimc_si128(key_schedule[2]);
    key_schedule[19] = _mm_aesimc_si128(key_schedule[1]);
}


//Шифруем
static void ak_aes128_enc(ak_skey skey, ak_pointer in, ak_pointer out){
    ak_uint8 * plainText = (ak_uint8 *) in;
    ak_uint8 * cipherText = (ak_uint8 *) out;
    __m128i m = _mm_loadu_si128((__m128i *) plainText);

    __m128i * key_schedule = (__m128i *) skey->data;
    DO_ENC_BLOCK(m, key_schedule);//вызываем 10 раундов

    _mm_storeu_si128((__m128i *) cipherText, m);
}

//дешифруем
static void ak_aes128_dec(ak_skey skey, ak_pointer in,ak_pointer out){
    ak_uint8 * plainText = (ak_uint8 *) out;
    ak_uint8 * cipherText = (ak_uint8 *) in;
    __m128i m = _mm_loadu_si128((__m128i *) cipherText);

    __m128i * key_schedule = (__m128i *) skey->data; 
    DO_DEC_BLOCK(m,key_schedule); //запускаем 10 раундов

    _mm_storeu_si128((__m128i *) plainText, m);
}

//маскирование не нужно, тк оно реализовано в интринзиках
int ak_set_aes_mask(ak_skey skey){
    return 0;
}

//маскирование не нужно, тк оно реализовано в интринзиках
int ak_set_aes_unmask(ak_skey skey){
    return 0;
}

static int ak_aes_delete_keys(ak_skey skey){
    int error = ak_error_ok;

     /* стандартные проверки */
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                     __func__ , "using a null pointer to secret key" );
    if( skey->data != NULL ) {
         /* теперь очистка и освобождение памяти */
        if(( error = ak_ptr_wipe( skey->data, sizeof(ak_aes_key), &skey->generator )) != ak_error_ok ) {
            ak_error_message( error, __func__, "incorrect wiping an internal data" );
            memset( skey->data, 0, sizeof(ak_aes_key));
        }
        free( skey->data );
        skey->data = NULL;
    }
    return error;
}

int ak_aes_schedule_keys(ak_skey skey){
     /* стандартные проверки */
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
    //if( skey->key_size != 32 ) return ak_error_message( ak_error_null_pointer, __func__ ,
     //                                                         "unsupported length of secret key" );
    /* удаляем мусор */
    if( skey->data != NULL ) ak_aes_delete_keys( skey );

    __m128i * key_schedule = (__m128i *) skey->data;
    ak_uint8 enc_key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    k_aes128_load_key(enc_key, key_schedule); 

}

int ak_bckey_create_aes( ak_bckey bkey){
    int error = ak_error_ok, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );
    
     if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to block cipher key context" );
    /* создаем ключ алгоритма шифрования и определяем его методы */
    if(( error = ak_bckey_create( bkey, 32, 16 )) != ak_error_ok )
        return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );
    
    bkey->schedule_keys = ak_aes_schedule_keys; 
    bkey->delete_keys = ak_aes_delete_keys;
    bkey->encrypt = ak_aes128_enc;
    bkey->decrypt = ak_aes128_dec;
    
    bkey->key.set_mask = ak_set_aes_mask;
    bkey->key.unmask = ak_set_aes_unmask;
    return error;
}


//Тест. Возвращает 0, если по сгенерированному шифртексту и ключам дешифровался искомый plain 
bool_t ak_libakrypt_test_aes(){
    ak_uint8 plain[]      = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    ak_uint8 enc_key[]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    ak_uint8 cipher[]     = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};
    ak_uint8 result_cipher[16];
    ak_uint8 result_plain[16];
    int out=0;
    __m128i key_schedule[20];
    ak_aes128_load_key(enc_key,key_schedule);
    ak_aes128_enc(key_schedule,plain,result_cipher);
    ak_aes128_dec(key_schedule,cipher,result_plain);
    if(memcmp(cipher,result_cipher,sizeof(cipher))) out=1;
    if(memcmp(plain,result_plain,sizeof(plain))) out|=2;

    struct bckey skey;
    if (ak_bckey_create_aes(&skey) != ak_error_ok) {
        printf("Проблема в ak_bckey_create_aes\n");
        return -1;
    }

    if (ak_bckey_set_key(&skey, enc_key, 128) != ak_error_ok){
        printf("Проблема в ak_bckey_set_key\n");
        return -1;
    }
    
    if (ak_bckey_encrypt_ecb(&skey, plain, result_plain, 7 ) != ak_error_ok) {
        printf("Проблема в ak_bckey_encrypt_ecb\n");
        return -1;
    }


    printf("AES-Шифрование\nНачальный ключ: ");
    for (int i = 0; i < 16; i++){
        printf("%X ", enc_key[i]);
    }
    printf("\nШифруемые данные: ");
    for (int i = 0; i < 16; i++){
        printf("%X ", plain[i]);
    }
    printf("\nРезультат шифрования: ");
    for (int i = 0; i < 16; i++){
        printf("%X ", result_plain[i]);
    }

    printf("\nРезультат дешифрования получившегося шифртекста:");
    for(int i = 0; i < 16; i++){
        printf("%X ", result_cipher[i]);
    }
    return (out == 0);
}

#endif