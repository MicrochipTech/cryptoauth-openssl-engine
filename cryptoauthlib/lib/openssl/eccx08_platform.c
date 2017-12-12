/**
 * \brief OpenSSL ENGINE Platform Hooks & Global Default Configuration
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
 *    Microchip integrated circuit.
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

/* This is the user defined encryption key */
uint8_t staticKey[ATCA_KEY_SIZE] = { 0x77 };

ATCAIfaceCfg* pCfg;

ATCAIfaceCfg* eccx08_get_iface_default(ATCAIfaceType iType)
{
    switch (iType)
    {
    //case ATCA_I2C_IFACE:
    //    return &cfg_ateccx08a_i2c_default;
    //case ATCA_SWI_IFACE:
    //    return &cfg_ateccx08a_swi_default;
    case ATCA_UART_IFACE:
        return &cfg_atecc508a_kitcdc_default;
    case ATCA_HID_IFACE:
        return &cfg_atecc508a_kithid_default;
    default:
        return NULL;
    }
}

/* Get the appropriate interface settings given an input key configuration */
int eccx08_get_iface_cfg(ATCAIfaceCfg* iface, eccx08_engine_key_t * key)
{
    int ret = ENGINE_OPENSSL_FAILURE;
    
    if (iface && key)
    {
        ATCAIfaceCfg* def = eccx08_get_iface_default(key->bus_type);

        if (def)
        {
            /* Copy the default settings */
            memcpy(iface, def, sizeof(ATCAIfaceCfg));

            /* Replace defaults with the key settings */
            switch (iface->iface_type)
            {
            case ATCA_I2C_IFACE:
                iface->atcai2c.bus = key->bus_num;
                iface->atcai2c.slave_address = key->device_num;
                break;
            case ATCA_SWI_IFACE:
                iface->atcaswi.bus = key->bus_num;
                break;
            default:
                break;
            }

            ret = ENGINE_OPENSSL_SUCCESS;
        }
    }
    return ret;
}


/* Initialize platform defaults */
int eccx08_platform_init(void)
{
    /* Get a pointer to the default configuration */
#ifdef ATCA_HAL_KIT_CDC
    pCfg = &cfg_atecc508a_kitcdc_default;
#elif ATCA_HAL_KIT_HID
    pCfg = &cfg_atecc508a_kithid_default;
#elif ATCA_HAL_I2C
    pCfg = &cfg_ateccx08a_i2c_default;
#endif

    eccx08_engine_config.device_key_slot = 0;
    eccx08_engine_config.ecdh_key_slot = 2;
    eccx08_engine_config.ecdh_key_count = 1;

    return ENGINE_OPENSSL_SUCCESS;
}

char * eccx08_strip_path(char * in_str)
{
    char * tmp = in_str;
    char * rv;

    if (!in_str)
        return "";
#ifdef _WIN32
    while (tmp = strchr(tmp, '\\'))
#else
    while (tmp = strchr(tmp, '/'))
#endif
    {
        rv = ++tmp;
    }

    return rv;
}
