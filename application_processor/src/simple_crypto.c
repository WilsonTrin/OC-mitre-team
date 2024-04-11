/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

// #if CRYPTO_EXAMPLE

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>
// #include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/random.h"
// #include "wolfssl/mcapi/crypto.h"
// #include "wolfssl/openssl/rsa.h"
// #include "wolfssl/openssl/pem.h"
// #include "wolfssl/wolfcrypt/rsa.h"
// #include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "host_messaging.h"
// #include "wolfssl/openssl/asn1.h"


/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    Aes ctx; // Context for encryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for encryption
    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_ENCRYPTION);
    if (result != 0)
        return result; // Report error


    // Encrypt each block
    for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
        result = wc_AesEncryptDirect(&ctx, ciphertext + i, plaintext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    Aes ctx; // Context for decryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for decryption
    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_DECRYPTION);
    if (result != 0)
        return result; // Report error

    // Decrypt each block
    for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
        result = wc_AesDecryptDirect(&ctx, plaintext + i, ciphertext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param len The length of the plaintext to encrypt
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    // Pass values to hash
    return wc_Md5Hash((uint8_t *)data, len, hash_out);
}

//Function converts a Public Key in PEM format to a WolfSSL RsaKey struct
RsaKey setPubRSAKey (char* pemPubKey)
{
    byte * outKey[1000];
    word32 size = 1000;
    word32 * pointer = &size;
    print_debug("%i", *pointer);
    print_hex_debug(pemPubKey, strlen(pemPubKey));
    Base64_Decode(pemPubKey, strlen(pemPubKey), outKey, pointer);
    // print_debug("%i", Base64_Decode("aGV5IG15IG5hbWUgaXMgbGFuY2U=", strlen("aGV5IG15IG5hbWUgaXMgbGFuY2U="), outKey, pointer));
    print_debug("here we go");
    print_debug("%i", *pointer);
    print_hex_debug(outKey, *pointer);
    unsigned char * result[*pointer];

    memcpy(result, outKey, *pointer);


    int pemSz=sizeof(result);
    print_debug("%i", pemSz);
    // print_debug(*result);
    //  int pemSz=sizeof(pemPubKey);
    DerBuffer* saveBuff;
    int saveBuffSz=0; 
   
    saveBuffSz=wc_PemToDer(result, pemSz, 12/* was 12 PUBLICKEY_TYPE*/, &saveBuff, NULL, NULL, NULL); //wc_PubKeyPemToDer(pemPubKey,pemSz,*saveBuff,saveBuffSz); // here?
    if (saveBuffSz<0)
    {
        print_debug("error pem to der %i",saveBuffSz);
    }
    RsaKey pub;
    word32 idx = 0;
    int ret = 0;
  
 
    wc_InitRsaKey(&pub, NULL); // not using heap hint. No custom memory
    ret = wc_RsaPublicKeyDecode(saveBuff, &idx, &pub, saveBuffSz);
    if( ret != 0 ) {
        print_debug("error generating key %i",ret);
    }

    return pub;

}

//Function converts a Private Key in PEM format to a WolfSSL RsaKey struct
RsaKey setPrivRSAKey (char* privPubKey)
{
    int pemSz=sizeof(privPubKey);
    char* saveBuff ;
    int saveBuffSz=0;

    saveBuffSz=wolfSSL_CertPemToDer(privPubKey,pemSz,*saveBuff,saveBuffSz,11); //RSA_TYPE I think

    RsaKey priv;
    word32 idx = 0;
    int ret = 0;
   
 
    wc_InitRsaKey(&priv, NULL); // not using heap hint. No custom memory
    ret = wc_RsaPrivateKeyDecode(saveBuff, &idx, &priv, saveBuffSz);
    if( ret != 0 ) {
        // error parsing private key
    }
    return priv;
}

// #endif
