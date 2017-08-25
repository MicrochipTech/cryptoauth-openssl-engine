/**
 * \file
 * \brief OS Abstraction Functions (Windows)
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

#include "atca_hal.h"

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the os abstraction layer
 *
   @{ */

#ifdef _WIN32
#include <windows.h>

/**
 * \brief Application callback for creating a mutex object
 * \param[IN/OUT] ppMutex location to receive ptr to mutex
 * \param[IN] pName Name of the mutex for systems using named objects
 */
ATCA_STATUS hal_os_create_mutex(void** ppMutex, const char *pName)
{
    if (!ppMutex)
    {
        return ATCA_BAD_PARAM;
    }

    /* To share a lock in a dll across processing the mutexes must be named */
    *ppMutex = CreateMutex(NULL, FALSE, pName);

    if (!*ppMutex)
    {
        return ATCA_GEN_FAIL;
    }

    return ATCA_SUCCESS;
}

/* 
 * \brief Application callback for destroying a mutex object
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_os_destroy_mutex(void* pMutex)
{
    if (!pMutex)
    {
        return ATCA_BAD_PARAM;
    }

    CloseHandle(pMutex);

    return ATCA_SUCCESS;
}


/*
 * \brief Application callback for locking a mutex
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_os_lock_mutex(void* pMutex)
{
    DWORD rv;

    if (!pMutex)
    {
        return ATCA_BAD_PARAM;
    }

    rv = WaitForSingleObject((HANDLE)pMutex, INFINITE);

    if (WAIT_OBJECT_0 == rv)
    {
        return ATCA_SUCCESS;
    }
    else if (WAIT_ABANDONED_0 == rv)
    {
        /* Lock was obtained but its because another process terminated so the 
        state is indeterminate and will probably need to be fixed */
        return ATCA_FUNC_FAIL;
    }
    else
    {
        return ATCA_GEN_FAIL;
    }
}

/*
 * \brief Application callback for unlocking a mutex
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_os_unlock_mutex(void* pMutex)
{
    ATCA_STATUS rv = ATCA_SUCCESS;

    if (!pMutex)
    {
        return ATCA_BAD_PARAM;
    }

    if (!ReleaseMutex((HANDLE)pMutex))
    {
        rv = ATCA_GEN_FAIL;
    }

    return rv;
}

#endif

/** @} */
