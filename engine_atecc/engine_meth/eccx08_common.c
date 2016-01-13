/**
 *  \file eccx08_common.c
 * \brief Implementation of OpenSSL ENGINE callback functions for ECC
 *        See reference code in ec_pmeth.c
 *
 * Copyright (c) 2015 Atmel Corporation. All rights reserved.
 *
 * \atmel_crypto_device_library_license_start
 *
 * \page License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Atmel nor the names of its contributors may be used to endorse
 *    or promote products derived from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <assert.h>
#include <stdarg.h>
#include <openssl/engine.h>
#include <openssl/ec.h>
#include <crypto/ec/ec_lcl.h>
#include <crypto/evp/evp.h>
#include <crypto/evp/evp_locl.h>
#include <crypto/asn1/asn1_locl.h>
#include <crypto/ossl_typ.h>
#include "ecc_meth.h"

// Define a version for the key format
#define KEY_FORMAT_VERSION   (1)

// Test ECC P256 private key definition
uint8_t test_priv_key[MEM_BLOCK_SIZE] = {
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
    0x27, 0x28, 0x29, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42,
};
// Test ECC P256 public key definition
uint8_t test_pub_key[MEM_BLOCK_SIZE*2] = {
    0xe9, 0xb8, 0x91, 0x9f, 0x3d, 0x76, 0x4a, 0x26, 0xa4, 0xa8, 0xf6, 0x2b, 0x53, 0xbe, 0xd7, 0xe3,
    0x14, 0x46, 0x33, 0xdd, 0xf2, 0x64, 0x98, 0xd0, 0xe9, 0x85, 0x70, 0xab, 0xe5, 0xb3, 0x06, 0xfd,
    0xdf, 0x91, 0x63, 0x84, 0x71, 0x7d, 0xdc, 0x68, 0x05, 0x79, 0x12, 0x86, 0x30, 0x73, 0xc5, 0x77,
    0xc5, 0xb3, 0x73, 0x95, 0x8b, 0x95, 0xaf, 0xd5, 0x49, 0x1f, 0x9f, 0x82, 0xe4, 0xeb, 0x77, 0x86,
};

// USER: Customize the following source file for the target platform
#include "platform.h"

/**
 * \brief A user defined function that fills a raw buffer (32 bytes) with the
 *  platform-specific encryption key.
 *
 *  USER: Platform needs to to provide secure storage for this encryption key
 *
 * \param[in,out] enckey Pointer to a buffer to fill with the encryption key data
 * \param[in] keysize The size of the enckey buffer (number of bytes should be MEM_BLOCK_SIZE)
 * \return 1 on success, 0 on error
 */
ATCA_STATUS eccx08_get_enc_key(uint8_t *enckey, int16_t keysize)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;

    if (enckey == NULL || keysize < ATCA_KEY_SIZE) {
        goto done;
    }
    memcpy(enckey, staticKey, sizeof(staticKey));
    status = ATCA_SUCCESS;
done:
    return status;
}

/**
 *  eccx08_eckey_fill_key()
 *
 * \brief Fills a raw buffer (32 bytes) with data to save into the
 *  private key structure
 *
 * \param[in,out] ptr Pointer to a buffer to fill the key data
 * \param[in] slot_id ATECCX08 slot ID
 * \param[in] serial_number 9 bytes of ATECCX08 serial number
 * \param[in] serial_len Size of the ATECCX08 serial number buffer
 * \return 1 on success, 0 on error
 */
int eccx08_eckey_fill_key(char *ptr, int size, uint8_t slot_id,
                          uint8_t *serial_number, int serial_len)
{
    int rc = 0;
    int len = 0;
    uint8_t key_format = KEY_FORMAT_VERSION;
    char *chip_name = "ATECCX08";

    if (size < MEM_BLOCK_SIZE) {
        goto done;
    }

    len = size;
    //Put 0xff around the token to see it clearly in the key file
    memset(ptr, 0xff, size);
    ptr += 8;

    //Version field
    memcpy(ptr, &key_format, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    len -= sizeof(uint8_t);
    //Chip name field
    memcpy(ptr, chip_name, strlen(chip_name));
    ptr += strlen(chip_name);
    len -= strlen(chip_name);
    //Serial number field
    memcpy(ptr, serial_number, serial_len);
    ptr += serial_len;
    len -= serial_len;
    //Slot ID field
    memcpy(ptr, &slot_id, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    len -= sizeof(uint8_t);

    assert(len >= 0);

    rc = 1;
done:
    return (rc);
}

/**
 *  eccx08_eckey_encode_in_privkey()
 *
 *  \brief Converts 32 bytes from ATECC508 format to the openssl EC_KEY
 *  structure. It allocates EC_KET structure and does not free
 *  it (must be a caller to free)
 *
 * \param[in/out] eckey Pointer to EC_KEY with Private key token on success
 * \param[in] slot_id ATECCX08 slot ID
 * \param[in] serial_number 9 bytes of ATECCX08 serial number
 * \param [in] serial_len Size of the ATECCX08 serial number buffer
 * \return 1 on success, 0 on error
 */
int eccx08_eckey_encode_in_privkey(EC_KEY *eckey, uint8_t slot_id, uint8_t *serial_number, int serial_len)
{
    int rc = 0;
    int ret = 0;
    int len = 0;
    BIGNUM *priv_key = eckey->priv_key;
    char *ptr = NULL;

    ptr = (char *)OPENSSL_malloc(MEM_BLOCK_SIZE);
    if (!ptr) {
        goto done;
    }
    ret = eccx08_eckey_fill_key(ptr, MEM_BLOCK_SIZE, slot_id, serial_number, serial_len);
    if (ret == 0) {
        goto done;
    }

    if (NULL == priv_key) {
        priv_key = BN_new();
    }
    if (NULL == priv_key) {
        goto done;
    }
    eckey->priv_key = priv_key;
    len = MEM_BLOCK_SIZE;

    if (priv_key) {
        BN_bin2bn(ptr, len, priv_key);
    } else {
        priv_key = BN_bin2bn(ptr, len, NULL);
    }

    rc = 1;
done:
    if (ptr) {
        OPENSSL_free(ptr);
    }
    return (rc);
}

/**
 *  eccx08_eckey_compare_privkey()
 *
 * \brief Checks if the private key in the openssl EC_KEY structure
 *  corresponds to the private key in the ATECCCX08 slot.
 *
 * \param[in,out] eckey Pointer to EC_KEY with Private key token on success
 * \param[in] slot_id ATECCX08 slot ID
 * \param[in] serial_number 9 bytes of ATECCX08 serial number
 * \param[in] serial_len Size of the ATECCX08 serial number buffer
 * \return 1 on success, 0 on error
 */
int eccx08_eckey_compare_privkey(EC_KEY *eckey, uint8_t slot_id, uint8_t *serial_number, int serial_len)
{
    int rc = 0;
    int ret = 0;
    int len = 0;
    BIGNUM *priv_key;
    char *ptr = NULL;
    char *raw_key = NULL;

    if (NULL == eckey) {
        goto done;
    }
    priv_key = eckey->priv_key;
    if (NULL == priv_key) {
        goto done;
    }

    len = MEM_BLOCK_SIZE;
    ptr = (char *)OPENSSL_malloc(len);
    if (!ptr) {
        goto done;
    }
    raw_key = (char *)OPENSSL_malloc(len);
    if (!raw_key) {
        goto done;
    }
    ret = eccx08_eckey_fill_key(ptr, len, slot_id, serial_number, serial_len);
    if (ret == 0) {
        goto done;
    }

    BN_bn2bin(priv_key, raw_key);

    if (0 != memcmp(raw_key, ptr, len)) {
        goto done;
    }

    rc = 1;
done:
    if (ptr) {
        OPENSSL_free(ptr);
    }
    if (raw_key) {
        OPENSSL_free(raw_key);
    }
    return (rc);
}

/**
 *  eccx08_generate_key()
 *
 * \brief Generates a 32-byte private key then replaces it with token
 *  data using the eccx08_eckey_encode_in_privkey() call
 *
 * \param[out] p_eckey Pointer to EC_KEY with Public Key on success
 * \param[in] serial_number 9 bytes of ATECCX08 serial number
 * \param[in] serial_len Size of the ATECCX08 serial number buffer
 * \return 1 on success, 0 on error
 */
int eccx08_generate_key(EC_KEY *eckey, uint8_t *serial_number, int serial_len)
{
    int ok = 0;
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *priv_key = NULL, *order = NULL;
    EC_POINT *pub_key = NULL;

    uint8_t slotid = TLS_SLOT_AUTH_PRIV;

    if (!eckey || !eckey->group) {
        ECerr(EC_F_EC_KEY_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((order = BN_new()) == NULL) goto err;
    if ((ctx = BN_CTX_new()) == NULL) goto err;

    if (eckey->priv_key == NULL) {
        priv_key = BN_new();
        if (priv_key == NULL) goto err;
    } else {
        priv_key = eckey->priv_key;
    }

    eckey->priv_key = priv_key;

    if (!EC_GROUP_get_order(eckey->group, order, ctx)) goto err;

    do if (!BN_rand_range(priv_key, order)) goto err;
    while (BN_is_zero(priv_key));

    ret = eccx08_eckey_encode_in_privkey(eckey, slotid, serial_number, ATCA_SERIAL_NUM_SIZE);
    if (!ret) goto err;

    if (eckey->pub_key == NULL) {
        pub_key = EC_POINT_new(eckey->group);
        if (pub_key == NULL) goto err;
    } else pub_key = eckey->pub_key;

    if (!EC_POINT_mul(eckey->group, pub_key, priv_key, NULL, NULL, ctx)) goto err;

    eckey->pub_key = pub_key;

    ok = 1;

err:
    if (order) BN_free(order);
    if (pub_key != NULL && eckey->pub_key == NULL) EC_POINT_free(pub_key);
    if (priv_key != NULL && eckey->priv_key == NULL) BN_free(priv_key);
    if (ctx != NULL) BN_CTX_free(ctx);
    return (ok);
}

/**
 *  eccx08_eckey_convert()
 *
 * \brief Converts raw 64 bytes of public key (ATECC508 format) to the
 *  openssl EC_KEY structure. It allocates EC_KEY structure and
 *  does not free it (must be a caller to free)
 *
 * \param[out] p_eckey Pointer to EC_KEY with Public Key on success
 * \param[in] raw_pubkey Raw public key, 64 bytes length 32-byte X following with 32-byte Y
 * \param[in] serial_number 9 bytes of ATECCX08 serial number
 * \param[in] serial_len Size of the ATECCX08 serial number buffer
 * \return 1 on success, 0 on error
 */
int eccx08_eckey_convert(EC_KEY **p_eckey, uint8_t *raw_pubkey, uint8_t *serial_number, int serial_len)
{
    int rc = 0;
    int ret = 0;
    EC_GROUP *ecgroup = NULL, *ecgroup_old = NULL;
    EC_KEY *eckey = *p_eckey;
    EC_POINT *ecpoint = NULL;
    BN_CTX *bnctx = NULL;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    char tmp_buf[MEM_BLOCK_SIZE * 2 + 1];


    /* Openssl raw key has a leading byte with conversion form id */
    tmp_buf[0] = POINT_CONVERSION_UNCOMPRESSED;
    memcpy(&tmp_buf[1], raw_pubkey, MEM_BLOCK_SIZE * 2);

    if (!eckey) {
        eckey = EC_KEY_new();
        if (!eckey) goto done;
    }
    ecgroup = eckey->group;
    if (!ecgroup) {
        ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ecgroup) goto done;
        EC_GROUP_set_point_conversion_form(ecgroup, form);
        EC_GROUP_set_asn1_flag(ecgroup, asn1_flag);
    }

    if (!eckey->group) {
        ret = EC_KEY_set_group(eckey, ecgroup);
        if (!ret) goto done;
    }

    ret = eccx08_generate_key(eckey, serial_number, serial_len);
    if (!ret) goto done;

    ecgroup = eckey->group;
    ecpoint = eckey->pub_key;

    if (!ecpoint) {
        ecpoint = EC_POINT_new(ecgroup);
        if (!ecpoint) goto done;
    }

    ret = EC_POINT_oct2point(ecgroup, ecpoint, tmp_buf, MEM_BLOCK_SIZE * 2 + 1, NULL);
    if (!ret) goto done;

    *p_eckey = eckey;
    rc = 1;
done:
    return (rc);
}

/**
 *
 * \brief Encrypt a BIGNUM data using AES-256 OFB mode.
 *
 * \param[in/out] number A pointer to the BIGNUM structure. The
 *       encrypted data replaces the plain text in this
 *       structure
 * \param[in] iv A pointer to a 16-byte IV buffer
 * \param[in] aes_key A pointer to a 32-byte AES key buffer
 * \return 1 for success
 */
int eccx08_BN_encrypt(BIGNUM *number, uint8_t *iv, uint8_t *aes_key)
{
    int ret = 0;
    int len;
    int cipher_len;
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;

    EVP_CIPHER_CTX *ctx = NULL;

    eccx08_debug("eccx08_BN_encrypt()\n");

    len = BN_num_bytes(number);
    plaintext = (char *)OPENSSL_malloc(len);
    if (!plaintext) {
        goto err;
    }
    ciphertext = (char *)OPENSSL_malloc(len);
    if (!ciphertext) {
        goto err;
    }
    BN_bn2bin(number, plaintext);

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        eccx08_debug("eccx08_BN_encrypt() context init failed\n");
        goto err;
    }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher.
     * We are using 256 bit AES (i.e. a 256 bit key), OFB mode (plain_len == cipher_len). 
     * The IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, aes_key, iv)) {
        eccx08_debug("eccx08_BN_encrypt() encrypt init failed\n");
        goto err;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, len)) {
        eccx08_debug("eccx08_BN_encrypt() encrypt update failed\n");
        goto err;
    }
    cipher_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        eccx08_debug("eccx08_BN_encrypt() encrypt final failed\n");
        goto err;
    }
    cipher_len += len;
    BN_bin2bn(ciphertext, cipher_len, number);
    ret = 1;

err:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (plaintext) {
        OPENSSL_free(plaintext);
    }
    if (ciphertext) {
        OPENSSL_free(ciphertext);
    }

    return ret;
}

/**
 *
 * \brief Decrypt a BIGNUM data using AES-256 OFB mode. Assuming
 *        that data there was encrypted using the
 *        eccx08_BN_encrypt().
 *
 * \param[in/out] number A pointer to the BIGNUM structure. The
 *       plain text replaces the encrypted data in this
 *       structure
 * \param[in] iv A pointer to a 16-byte IV buffer
 * \param[in] aes_key A pointer to a 32-byte AES key buffer
 * \return 1 for success
 */
int eccx08_BN_decrypt(BIGNUM *number, uint8_t *iv, uint8_t *aes_key)
{
    int ret = 0;
    int len;
    int plain_len;
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;

    EVP_CIPHER_CTX *ctx = NULL;

    eccx08_debug("eccx08_BN_decrypt()\n");

    len = BN_num_bytes(number);
    plaintext = (char *)OPENSSL_malloc(len);
    if (!plaintext) {
        goto err;
    }
    ciphertext = (char *)OPENSSL_malloc(len);
    if (!ciphertext) {
        goto err;
    }
    BN_bn2bin(number, ciphertext);

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        eccx08_debug("eccx08_BN_decrypt() context init failed\n");
        goto err;
    }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher.
     * We are using 256 bit AES (i.e. a 256 bit key), OFB mode (plain_len == cipher_len). 
     * The IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, aes_key, iv)) {
        eccx08_debug("eccx08_BN_decrypt() decrypt init failed\n");
        goto err;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, len)) {
        eccx08_debug("eccx08_BN_decrypt() decrypt update failed\n");
        goto err;
    }
    plain_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        eccx08_debug("eccx08_BN_decrypt() decrypt final failed\n");
        goto err;
    }
    plain_len += len;
    BN_bin2bn(plaintext, plain_len, number);
    ret = 1;

err:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (plaintext) {
        OPENSSL_free(plaintext);
    }
    if (ciphertext) {
        OPENSSL_free(ciphertext);
    }

    return ret;
}

#ifdef ECC_DEBUG
/**
 *
 * \brief Debugging function to print out ateccx08 messages. For
 *        detail see help on a standard printf() function
 *
 * \param[in] fmt the format string
 * \return 1 for success
 */
int eccx08_debug(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "ATECCX08: ");
    vfprintf(stderr, fmt, args);
    va_end(args);
    return (1);
}
#else
int eccx08_debug(const char *fmt, ...)
{
    return (1);
}
#endif
