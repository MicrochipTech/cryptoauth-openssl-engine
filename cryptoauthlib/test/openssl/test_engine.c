

#if defined(_WIN32) || defined(__linux__)

#include <openssl/ssl.h>
#include <openssl/conf.h>
#include "../test/unity.h"
#include "../test/unity_fixture.h"
#include "../lib/openssl/eccx08_engine.h"
#include "../lib/openssl/eccx08_engine_internal.h"

#define TEST_ENGINE_RAND        0
#define TEST_ENGINE_SHA256      0
#define TEST_ENGINE_COMMANDS    0
#define TEST_ENGINE_ECDH        0
#define TEST_ENGINE_ECDSA       1
#define TEST_ENGINE_CERT        1

/* This option registers all configured engine functionality with OpenSSL
 this means some operations can be slow - certificate validation could end up 
 using the device for SHA256 & ECDSA verify operations */
#define TEST_REGISTER_ALL       1

static ENGINE *ateccx08_engine;
static char fail_msg_buf[1024];

/* A helper macro to make the tests look cleaner */
#define ENGINE_TEST_FAIL(msg)   { (void)snprintf(fail_msg_buf, sizeof(fail_msg_buf), "%s: %s\n", msg, ERR_error_string(ERR_get_error(), NULL)); \
                                  fail_msg_buf[sizeof(fail_msg_buf) - 1] = 0; TEST_FAIL_MESSAGE(fail_msg_buf); }

/**
* \brief Integration Tests of Device Features
*/
TEST_GROUP(atca_engine);

TEST_SETUP(atca_engine)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
//    ERR_print_errors_fp(stderr);

    /* An Application can call this function - but if the library is unloaded 
        and cleaned up the config file won't be reloaded since this function 
        is only allowed to run once */
    //OPENSSL_config(NULL);
        
    /* For applications loading and unloading the library this is the way to load the configuration
        Also it will alert when the config file can not be found */
    ENGINE_load_dynamic();
    if (!CONF_modules_load_file(NULL, NULL, CONF_MFLAGS_DEFAULT_SECTION))
    {
        ENGINE_TEST_FAIL("Config failed to load");
    }

    /* Load the engine for testing */
    ateccx08_engine = ENGINE_by_id("ateccx08");

    if (ateccx08_engine == NULL)
    {
        ENGINE_TEST_FAIL("Engine failed to load");
    }

    if (!ENGINE_init(ateccx08_engine))
    {
        ENGINE_TEST_FAIL("Engine failed to initialize");
    }

#if TEST_REGISTER_ALL
    /* Register all engine functionality with OpenSSL */
    if (!ENGINE_register_complete(ateccx08_engine))
    {
        ENGINE_TEST_FAIL("Engine register failed");
    }
#endif
}

TEST_TEAR_DOWN(atca_engine)
{
    /* A bit excessive in relation to the library teardown - this is the worst
        case scenario for removing library resources */
    snprintf(fail_msg_buf, sizeof(fail_msg_buf), "\r\n");

    

//    printf("Call FIPS_mode_set\n");
    FIPS_mode_set(0);
//    printf("Call CRYPTO_set_locking_callback\n");
//    CRYPTO_set_locking_callback(NULL);
//    printf("Call CRYPTO_set_id_callback\n");
//    CRYPTO_set_id_callback(NULL);
//    printf("Call ERR_remove_state\n");
    ERR_remove_state(0);
//    printf("Call ERR_remove_thread_state\n");
//    ERR_remove_thread_state(0);

//    printf("Call SSL_COMP_free_compression_methods\n");
//    SSL_COMP_free_compression_methods();
//    printf("Call ENGINE_cleanup\n");
    ENGINE_cleanup();
    ateccx08_engine = NULL;

//    printf("Call CONF_modules_free\n");
    CONF_modules_free();
//    printf("Call CONF_modules_unload\n");
    CONF_modules_unload(1);
//    printf("Call COMP_zlib_cleanup\n");
//    COMP_zlib_cleanup();
//    printf("Call ERR_free_strings\n");
//    ERR_free_strings();
//    printf("Call EVP_cleanup\n");
    EVP_cleanup();
//    printf("Call CRYPTO_cleanup_all_ex_data\n");
    CRYPTO_cleanup_all_ex_data();
}

TEST(atca_engine, init)
{
    /* If this test runs then the initialization was successful */
    TEST_ASSERT(true);
}


TEST(atca_engine, rand)
{
#if TEST_ENGINE_RAND
    unsigned char rand_buf[512];
    int i;
    int count = 0;

    memset(rand_buf, 0xA5, sizeof(rand_buf));

    /* Only needed if the functionality isn't registered */
    //if (!ENGINE_set_default_RAND(ateccx08_engine))
    //{
    //    ENGINE_TEST_FAIL("Unable to set default RAND");
    //}

    if (!RAND_bytes(rand_buf, 512))
    {
        ENGINE_TEST_FAIL("Failed to read RAND bytes");
    }

    for (i = 0; i < sizeof(rand_buf); i++)
    {
    //    if (!(i % 16)) printf("\n");
    //    printf("%02x ", rand_buf[i]);
        if (0xA5 == rand_buf[i])
        {
            count++;
        }
    }
    //printf("\n");
    TEST_ASSERT_MESSAGE(count < 5, "Too many bytes equal the init value - check RNG");
#else
    TEST_IGNORE_MESSAGE("Skiping Test");
#endif
}

static char digest[32];
static unsigned int digestSize;

TEST(atca_engine, sha256)
{
    /* A valid digest is needed for the ECDSA test later on */
#if TEST_ENGINE_SHA256 || TEST_ENGINE_ECDSA
    /* Only needed if the functionality isn't registered */
#if !TEST_REGISTER_ALL && ATCA_OPENSSL_ENGINE_ENABLE_SHA256
    if (!ENGINE_set_default_digests(ateccx08_engine))
    {
        ENGINE_TEST_FAIL("Failed to register SHA256");
    }
#endif

    /* Test Vectors */
    const char nist_hash_msg1[] = "abc";
    const uint8_t nist_hash_msg1_dig[] = {
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
        0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
    };
    const char nist_hash_msg2[] = "";
    const uint8_t nist_hash_msg2_dig[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    const char nist_hash_msg3[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const uint8_t nist_hash_msg3_dig[] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
    };

    char * msg = nist_hash_msg3;
    uint8_t * digest_ref = nist_hash_msg3_dig;

    memset(digest, 0, sizeof(digest));

    EVP_MD_CTX *evp_ctx = EVP_MD_CTX_create();
#if ATCA_OPENSSL_ENGINE_ENABLE_SHA256
    EVP_DigestInit_ex(evp_ctx, EVP_sha256(), ateccx08_engine);
#else
    EVP_DigestInit(evp_ctx, EVP_sha256());
#endif
    EVP_DigestUpdate(evp_ctx, (unsigned char*)msg, strlen(msg));
    EVP_DigestFinal(evp_ctx, digest, &digestSize);

    //printf("Digest Final Digest size:%d\n", digestSize);
    //for (int i = 0; i < digestSize; i++) {
    //    if (!(i % 16))
    //    {
    //        printf("\n");
    //    }
    //    printf("%02x ", digest[i]);
    //}
    //printf("\n");
    EVP_MD_CTX_destroy(evp_ctx);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(digest_ref, digest, 32);
#else
    TEST_IGNORE_MESSAGE("Skiping Test");
#endif
}

TEST(atca_engine, command)
{
#if TEST_ENGINE_COMMANDS
    if (!ENGINE_ctrl(ateccx08_engine, ECCX08_CMD_GET_VERSION, NULL, NULL, 0))
    {
        ENGINE_TEST_FAIL("Failed to execute command");
    }
    TEST_ASSERT(true);
#else
    TEST_IGNORE_MESSAGE("Skiping Test");
#endif
}

TEST(atca_engine, ecdh)
{
#if TEST_ENGINE_ECDH
    eckey = EC_KEY_new();

    unsigned char agreed_value[200];

    printf("Setting default ECDH to engine\n");
    sslerr = ENGINE_set_default_ECDH(ateccx08_engine);
    printf("Result Code: %d\n", sslerr);

    ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    pub_key = EC_KEY_get0_public_key(eckey);

    ecdh = EC_KEY_new();
    EC_KEY_set_group(ecdh, ec_group);
    sslerr = EC_KEY_set_private_key(ecdh, EC_KEY_get0_private_key(eckey));

    int agreed_value_len = ECDH_compute_key(agreed_value, 200, pub_key, ecdh, NULL);

    printf("ATECCx08: Agreed Value: %d\n", agreed_value_len);
    for (int i = 0; i < agreed_value_len; i++) {
        printf("%x", agreed_value[i]);
    }
    printf("\n");
#else
    TEST_IGNORE_MESSAGE("Skiping Test");
#endif
}

TEST(atca_engine, ecdsa)
{
#if TEST_ENGINE_ECDSA
    unsigned char sig[256];
    unsigned int sigsize;
    BIO* bio_in;
    X509 *certificate;
    EVP_PKEY *pubKey;
    EC_KEY * pub_eckey;
    EC_KEY * eckey = EC_KEY_new();
    int sslerr;

    /* Only needed if the functionality isn't registered */
#if !TEST_REGISTER_ALL
    if (!ENGINE_set_default_ECDSA(ateccx08_engine))
    {
        ENGINE_TEST_FAIL("Unable to set default ECDSA");
    }
#endif

    if (!ECDSA_sign(0, digest, digestSize, sig, &sigsize, eckey))
    {
        ENGINE_TEST_FAIL("Sign Failed");
    }

    //printf("Signature size: %d, Result Code: %d\n", sigsize, sslerr);
    //printf("Signature: ");
    //for (int i = 0; i < sigsize; i++) {
    //    printf("%02x", sig[i]);
    //}
    //printf("\n");

    /* From cert */
    //bio_in = BIO_new_file("./ownCert.pem", "r");
    //if (bio_in == NULL) {
    //    printf("could not read public key file\n");
    //    exit(1);
    //}
    //
    //certificate = X509_new();
    //if (PEM_read_bio_X509(bio_in, &certificate, 0, NULL) == NULL) {
    //    printf("could not read  certificate from public key file\n");
    //    exit(1);
    //}
    //

    //pubKey = X509_get_pubkey(certificate);

    /* From ATECCx08 generator */
    pubKey = ENGINE_load_public_key(ateccx08_engine, NULL, NULL, NULL);
    if (!pubKey)
    {
        ENGINE_TEST_FAIL("Failed to load public key");
    }

    pub_eckey = EVP_PKEY_get1_EC_KEY(pubKey);

    sslerr = ECDSA_verify(0, digest, digestSize, sig, sigsize, pub_eckey);

    printf("Verify Result: %s(%d) %s\n", (1 == sslerr) ? "Verified" : "Not Verified",
        sslerr, (-1 == sslerr) ? ERR_error_string(ERR_get_error(), NULL) : "");

    EVP_PKEY_free(pubKey);
    EC_KEY_free(eckey);
#else
    TEST_IGNORE_MESSAGE("Skiping Test");
#endif
}

/** \brief Test loading/reconstructing the device certificate - will fail if 
    the engine was built with ATCA_OPENSSL_ENGINE_STATIC_CONFIG set to 0 */
TEST(atca_engine, cert)
{
#if TEST_ENGINE_CERT
    X509 * pCert = NULL;
    uint8_t * buf = NULL;
    size_t buf_len = 0;
    EVP_PKEY *pubKey = NULL;
    int sslerr;

#if !ATCA_OPENSSL_ENGINE_STATIC_CONFIG
    extern const atcacert_def_t g_test_cert_def_0_device;
    extern const atcacert_def_t g_test_cert_def_1_signer;

    g_cert_def_1_signer_ptr = eccx08_cert_copy(&g_test_cert_def_1_signer);
    g_cert_def_2_device_ptr = eccx08_cert_copy(&g_test_cert_def_0_device);
#endif

    if (!ENGINE_load_ssl_client_cert(ateccx08_engine, NULL, NULL, &pCert, NULL, NULL, NULL, NULL))
    {
        ENGINE_TEST_FAIL("Failed to load device certificate");
    }

    buf_len = i2d_X509(pCert, &buf);

    //if (buf_len && buf)
    //{
    //    printf("Device Certificate:\n");
    //    for (int i = 0; i <buf_len; i++) {
    //        if (0 == (i % 16))
    //        {
    //            printf("\n");
    //        }
    //        printf("%02x ", buf[i]);
    //    }
    //    printf("\n");
    //}

    pubKey = X509_get_pubkey(pCert);
    if (!pubKey)
    {
        ENGINE_TEST_FAIL("Failed to load public key");
    }

    // pubKey = ENGINE_load_public_key(ateccx08_engine, NULL, NULL, NULL);
    // if (!pubKey)
    // {
    //     ENGINE_TEST_FAIL("Failed to load public key");
    // }


    sslerr = X509_verify(pCert, pubKey);

    if (pCert)
    {
        X509_free(pCert);
    }

    if (pubKey)
    {
        EVP_PKEY_free(pubKey);
    }

    if (buf)
    {
        OPENSSL_free(buf);
    }

    if (ENGINE_OPENSSL_ERROR == sslerr)
    {
        ENGINE_TEST_FAIL("Verify operation failed to complete");
    }
    else if(ENGINE_OPENSSL_FAILURE == sslerr)
    {
        TEST_FAIL_MESSAGE("Certificate is invalid")
    }
    else
    {
        TEST_ASSERT(true);
    }
#else
    TEST_IGNORE_MESSAGE("Skiping Test");
#endif
}
//TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

TEST_GROUP_RUNNER(atca_engine)
{
    RUN_TEST_CASE(atca_engine, init);
#if TEST_ENGINE_RAND
    RUN_TEST_CASE(atca_engine, rand);
#endif

#if TEST_ENGINE_SHA256 || TEST_ENGINE_ECDSA
    RUN_TEST_CASE(atca_engine, sha256);
#endif

#if TEST_ENGINE_COMMANDS
    RUN_TEST_CASE(atca_engine, command);
#endif

#if TEST_ENGINE_ECDH
    RUN_TEST_CASE(atca_engine, ecdh);
#endif

#if TEST_ENGINE_ECDSA
    RUN_TEST_CASE(atca_engine, ecdsa);
#endif

#if TEST_ENGINE_CERT
    RUN_TEST_CASE(atca_engine, cert);
#endif
}

void RunAllEngineTests(void)
{
    RUN_TEST_GROUP(atca_engine);
}


#endif