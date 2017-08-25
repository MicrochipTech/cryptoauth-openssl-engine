/**
 * \brief OpenSSL ENGINE - Main (bind/management interface) entry point 
 *
 * \copyright Copyright (c) 2017 Microchip Technology Inc. and its subsidiaries (Microchip). All rights reserved.
 *
 * \page License
 *
 * You are permitted to use this software and its derivatives with Microchip
 * products. Redistribution and use in source and binary forms, with or without
 * modification, is permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Microchip may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with a
 *     Microchip integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY MICROCHIP "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL MICROCHIP BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "eccx08_engine.h"
#include "eccx08_engine_internal.h"

/* Constants used when creating the ENGINE */
static const char * const engine_eccx08_id = ECCX08_ENGINE_ID;
static const char * const engine_eccx08_name = ECCX08_ENGINE_NAME;
static const char * const engine_eccx08_mutex_name = ECCX08_ENGINE_ID "_" ECCX08_ENGINE_VERSION;

/* Global Engine Configuration Structure */
eccx08_engine_config_t eccx08_engine_config;

/* Manage a global lock with locked state (1 - Ours, 0 - Not Ours) */
struct {
    void* handle;
    int state;
} global_lock;

/** \brief Lock the global mutex */
ATCA_STATUS eccx08_global_lock(void)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    if (!global_lock.handle)
    {
        if (ATCA_SUCCESS != (status = hal_os_create_mutex(&global_lock.handle, engine_eccx08_mutex_name)))
        {
            return status;
        }
        global_lock.state = 0;
    }

    if (!global_lock.state)
    {
        status = hal_os_lock_mutex(global_lock.handle);
        if (ATCA_FUNC_FAIL == status)
        {
            /* Mutex was obtained but we're in an unknown state */
            atca_delay_ms(1500);
            status = ATCA_SUCCESS;
        }

        if (ATCA_SUCCESS == status)
        {
            global_lock.state = 1;
        }
    }
    
    return status;
}

/** \brief Unlock the global mutex */
ATCA_STATUS eccx08_global_unlock(void)
{
    ATCA_STATUS status = hal_os_unlock_mutex(global_lock.handle);

    if (ATCA_SUCCESS == status)
    {
        global_lock.state = 0;
    }

    return status;
}

/** \brief Thin abstraction on atcab_init that incorporates a global locking mechanism*/
ATCA_STATUS atcab_init_safe(ATCAIfaceCfg *cfg)
{
    ATCA_STATUS status = eccx08_global_lock();

    if (ATCA_SUCCESS != status)
    {
        return status;
    }

    return atcab_init(cfg);
}

/** \brief Thin abstraction on atcab_release that incorporates a global locking mechanism*/
ATCA_STATUS atcab_release_safe(void)
{
    ATCA_STATUS status = eccx08_global_lock();

    if (ATCA_SUCCESS != status)
    {
        return status;
    }

    status = atcab_release();

    (void)eccx08_global_unlock();

    return status;
}

/**
*  \brief Deinitialize the engine.
*
* \param[in] e A pointer to Engine structure that completely describes the engine
* \return For success return 1
*/
static int eccx08_destroy(ENGINE *e)
{
    DEBUG_ENGINE("Entered\n");

    if (hal_os_destroy_mutex(global_lock.handle))
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    global_lock.state = 0;
    global_lock.handle = NULL;

    DEBUG_ENGINE("Finished\n");

    return ENGINE_OPENSSL_SUCCESS;
}

/**
*  \brief Initialization the ateccx08 engine.
*
* \param[in] e A pointer to Engine structure that completely describes the engine
* \return For success return 1
*/
static int eccx08_init(ENGINE *e)
{
    DEBUG_ENGINE("Entered\n");

    if (!global_lock.handle)
    {
        if (hal_os_create_mutex(&global_lock.handle, engine_eccx08_mutex_name))
        {
            return ENGINE_OPENSSL_FAILURE;
        }
        global_lock.state = 0;
    }

    /* Perform basic library initialization */
    eccx08_cert_init();
    eccx08_platform_init();
#if ATCA_OPENSSL_ENGINE_ENABLE_RAND
    eccx08_rand_init();
#endif

    return ENGINE_OPENSSL_SUCCESS;
}

/**
*
* \brief Complete all functions before deinitialization of the ateccx08 engine
*
* \param[in] e A pointer to Engine structure that completely describes the engine
* \return 1 for success
*/
static int eccx08_finish(ENGINE *e)
{
    DEBUG_ENGINE("Entered\n");

    eccx08_cert_cleanup();
    eccx08_ecdsa_cleanup();
    eccx08_pkey_meth_cleanup();

    return ENGINE_OPENSSL_SUCCESS;
}

/**
*  \brief Binds ATECCx08 Engine to OpenSSL crypto API
*
* \param[in] e A pointer to Engine structure that completely describes the engine
* \param[in] id String to identify the Engine implementation (e.g. "ateccx08")
* \return For success return 1
*/
static int bind_helper(ENGINE *e, const char *id)
{
    int rv = ENGINE_OPENSSL_FAILURE;
    int step = 0;

    DEBUG_ENGINE("Entered\n");
    if (id && (strcmp(id, engine_eccx08_id) != 0)) {
        return ENGINE_OPENSSL_FAILURE;
    }

    do
    {
        /* Register Engine Basics */
        if (!ENGINE_set_id(e, engine_eccx08_id))
            break;

        step++;
        if (!ENGINE_set_name(e, engine_eccx08_name))
            break;

        step++;
        if (!ENGINE_set_init_function(e, eccx08_init))
            break;

        step++;
        if (!ENGINE_set_destroy_function(e, eccx08_destroy))
            break;

        step++;
        if (!ENGINE_set_finish_function(e, eccx08_finish))
            break;

        step++;
        if (!ENGINE_set_ctrl_function(e, eccx08_cmd_ctrl))
            break;

        step++;
        if (!ENGINE_set_cmd_defns(e, eccx08_cmd_defns))
            break;

        /* Hardware Support Interfaces */
        step++;
#if ATCA_OPENSSL_ENGINE_ENABLE_RAND
        if (!ENGINE_set_RAND(e, &eccx08_rand))
            break;
#endif

        step++;
#if ATCA_OPENSSL_ENGINE_ENABLE_SHA256
        if (!ENGINE_set_digests(e, eccx08_sha256_selector))
            break;
#endif

        step++;
#if ATCA_OPENSSL_ENGINE_ENABLE_CERTS
        if (!ENGINE_set_load_ssl_client_cert_function(e, eccx08_cert_load_client))
            break;
#endif

        step++;
#if ATCA_OPENSSL_ENGINE_ENABLE_CIPHERS
        if (!eccx08_cipher_init())
            break;
        if (!ENGINE_set_ciphers(e, ENGINE_CIPHERS_PTR f))
            break;
#endif

        step++;
#if ATCA_OPENSSL_ENGINE_ENABLE_ECDH && !defined(OPENSSL_NO_ECDH)
        {
            ECDH_METHOD * ecdh_method_ptr = NULL;
            if (!eccx08_ecdh_init(&ecdh_method_ptr))
                break;
            if (!ENGINE_set_ECDH(e, ecdh_method_ptr))
                break;
        }
#endif

        step++;
#if ATCA_OPENSSL_ENGINE_ENABLE_ECDSA && !defined(OPENSSL_NO_ECDSA)
        {
            ECDSA_METHOD * ecdsa_meth_ptr = NULL;
            if (!eccx08_ecdsa_init(&ecdsa_meth_ptr))
                break;
            if (!ENGINE_set_ECDSA(e, ecdsa_meth_ptr))
                break;
        }
#endif

        step++;
        if (!ENGINE_set_load_pubkey_function(e, eccx08_load_pubkey))
            break;

        step++;
        if (!eccx08_pkey_meth_init())
            break;
        if (!ENGINE_set_pkey_meths(e, eccx08_pmeth_selector))
            break;

        rv = ENGINE_OPENSSL_SUCCESS;
    } while (0);
    
    if (rv)
    {
        DEBUG_ENGINE("Succeeded\n");
    }
    else
    {
        DEBUG_ENGINE("FAILED on Step: %d, Error: %d\n", step, ERR_peek_error());
    }

    return rv;
}

#ifdef ENGINE_DYNAMIC_SUPPORT
IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper);
#endif

/**
 * \brief An engine entry point. As this is only ever called
 * once, there's no need for locking (indeed - the lock will
 * already be held by our caller!!!)
 */
static ENGINE* ENGINE_ateccx08(void)
{
    DEBUG_ENGINE("Entered\n");
    ENGINE *eng = ENGINE_new();

    if (!eng) {
        return NULL;
    }
    if (!bind_helper(eng, engine_eccx08_id)) {
        ENGINE_free(eng);
        return NULL;
    }

    return eng;
}

/**
 *  \brief Load ATECCx08 Engine
 */
#ifdef ENGINE_DYNAMIC_SUPPORT
static
#endif
void ENGINE_load_ateccx08(void)
{
    DEBUG_ENGINE("Entered\n");
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = ENGINE_ateccx08();
    if (!toadd) return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}

