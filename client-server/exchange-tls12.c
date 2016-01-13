/**
 *  \file exchange-tls12.c
 * \brief TLS1.2 client/server exchange utility. It is an example
 * of the programmatic use of the ateccx08 engine for TLS1.2
 * exchange. This file is the main entry point. Call
 * "./exchange-tls12 -h" for help. For details see
 * https://wiki.openssl.org/index.php/SSL/TLS_Client and
 * https://wiki.openssl.org/index.php/Simple_TLS_Server
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


#include "tlsutil.h"

/* Defined in the tlsutil.c following an example in the openssl/apps/s_cb.c file */
extern int verify_depth;

/**
 *
 * \brief Print a short help on "./exchange-tls12 -h",
 *        "./exchange-tls12 -?", or for an invalid arguments.
 *
 */
void usage(void)
{
    printf("\n\nUsage:\n"
           "\t./exchange-tls12 -s -c <cipher_list> "
           "-p <ca_path> -b <chain_file>"
           "-f <cert_file> -k <key_file> -d <depth>"
           "-C <cmd> [-E] [-e ateccx08]"
           "[-I <IP_address>] [-P <port_number>]"
           " [-v] [h|?]");
    printf("\n\nWhere:\n");
    printf("\t-C <cmd> - run a command through the engine. Commands are:\n"
           "\t\tECCX08_CMD_GET_VERSION:\t\t %d\n"
           "\t\tECCX08_CMD_GET_SIGNER_CERT:\t %d\n"
           "\t\tECCX08_CMD_GET_PUB_KEY:\t\t %d\n"
           "\t\tECCX08_CMD_GET_DEVICE_CERT:\t %d\n"
           "\t\tECCX08_CMD_VERIFY_SIGNER_CERT:\t %d\n"
           "\t\tECCX08_CMD_VERIFY_DEVICE_CERT:\t %d\n"
           "\t\tECCX08_CMD_GET_ROOT_CERT:\t %d\n"
           "\t\tECCX08_CMD_EXTRACT_ALL_CERTS:\t %d\n"
           "\t\tECCX08_CMD_GET_PRIV_KEY:\t %d\n",
           ECCX08_CMD_GET_VERSION,
           ECCX08_CMD_GET_SIGNER_CERT,
           ECCX08_CMD_GET_PUB_KEY,
           ECCX08_CMD_GET_DEVICE_CERT,
           ECCX08_CMD_VERIFY_SIGNER_CERT,
           ECCX08_CMD_VERIFY_DEVICE_CERT,
           ECCX08_CMD_GET_ROOT_CERT,
           ECCX08_CMD_EXTRACT_ALL_CERTS,
           ECCX08_CMD_GET_PRIV_KEY);
    printf("\t-E Extract all certificates and save to files in /tmp directory\n");
    printf("\t-c <cipher_list> specify the cipher list, utility in Client mode\n");
    printf("\t-s Use the utility in Server mode\n");
    printf("\t-p <ca_path> - Path to CA (Certificate Authority)\n");
    printf("\t-b <chain_file> - Chain File Name (Certificate Bundle)\n");
    printf("\t-f <cert_file> - Certificate File Name\n");
    printf("\t-k <key_file> - Private Key File Name\n");
    printf("\t-e <engine ID> Use utility with an engine (supported ateccx08 only)\n");
    printf("\t-d <depth> - the maximum length of the server certificate chain\n");
    printf("\t-I <IP_address> - optional server IP address (127.0.0.1 if not provided)\n");
    printf("\t-P <port_number> - optional server port number (49917 if not provided)\n");
    printf("\t-v \t- print the utility version\n"
           "\t-h \t- This message\n"
           "\t-? \t- This message\n"
          );
    exit(1);
}

/**
 *
 * \brief Main exchange-tls12 function. For help on arguments
 *        see the usage() above.
 *
 * \param[in] argc - the number of arguments passed into the
 *       command line
 * \param[in] argv - a pointer to the array of arguments
 * \return 0 for success
 */
int main(int argc, char *argv[])
{
    int err = 0;
    int cmd = -1;
    char ch;
    uint32_t is_server = 0;
    uint32_t is_client = 0;
    char *ca_path = NULL;
    char *chain_file = NULL;
    char *cert_file = NULL;
    char *key_file = NULL;
    char *engine_id = NULL;
    char *cipher_list = NULL;
    char *ip_address = "127.0.0.1";
    uint16_t port_number = PORT_NUMBER_DEFAULT;
    char cwd[200];
    char cmd_buffer[256];
    int buf_len = 128;

    verify_depth = 0;

    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        fprintf(stderr, "Current working dir: %s\n", cwd);
    } else {
        fprintf(stderr, "getcwd() error");
        return 100;
    }
    snprintf(cmd_buffer, 256, "%s/certstore", cwd);

    while ((ch = getopt(argc, argv, "C:Ec:sp:b:f:k:e:d:I:P:vh?")) != (char)-1) {
        switch (ch) {
            case 'C':
                cmd = strtol(optarg, NULL, 0);
                break;
            case 'E':
                cmd = ECCX08_CMD_EXTRACT_ALL_CERTS;
                break;
            case 'c':
                is_client = 1;
                cipher_list = strdup(optarg);
                break;
            case 's':
                is_server = 1;
                break;
            case 'p':
                ca_path = strdup(optarg);
                break;
            case 'b':
                chain_file = strdup(optarg);
                break;
            case 'f':
                cert_file = strdup(optarg);
                break;
            case 'k':
                key_file = strdup(optarg);
                break;
            case 'e':
                engine_id = strdup(optarg);
                break;
            case 'd':
                verify_depth = strtol(optarg, NULL, 0);
                break;
            case 'I':
                ip_address = strdup(optarg);
                break;
            case 'P':
                port_number = strtol(optarg, NULL, 0);
                break;
            case 'v':
                printf("Exchange version = %s\n", EXCHANGE_VERSION);
                cmd = ECCX08_CMD_GET_VERSION;
                break;
            case 'h':
            case '?':
            default:
                usage();
                break;
        }
    }

    if (cmd != -1) {
        if (!engine_id) {
            fprintf(stderr, "\nNo Engine specified - cannot run a command\n");
            return (10);
        }
        init_openssl();
        err = setup_engine(engine_id);
        if (err == 0) {
            err = 19;
            goto done;
        }
        err = run_engine_cmds(engine_id, cmd, cmd_buffer, buf_len);
        if (err == 0) {
            err = 20;
            goto done;
        }
        if ('\0' != cmd_buffer) {
            printf("%s\n", cmd_buffer);
        }
        err = 0;
        goto done;
    }

    if ((is_server || is_client) == 0) {
        fprintf(stderr, "\nMust specify -c or -s option");
        usage();
    } else if ((is_server && is_client) == 1) {
        fprintf(stderr, "\nCannot specify both -c or -s options");
        usage();
    }
    if (!ca_path) {
        fprintf(stderr, "\nMust specify CA path");
        usage();
    }
    if (!chain_file) {
        fprintf(stderr, "\nMust specify Chain File (certificate bundle)");
        usage();
    }
    if (!cert_file) {
        fprintf(stderr, "\nMust specify Certificate File");
        usage();
    }
    if (!key_file) {
        fprintf(stderr, "\nMust specify Private Key File");
        usage();
    }

    if (!engine_id) {
        fprintf(stderr, "\nNo Engine specified - using software crypto/ssl libraries\n");
    }

    if (is_server) {
        err = connect_server(engine_id, ca_path, chain_file, cert_file, key_file,
                   ip_address, port_number);
    } else {
        err = connect_client(engine_id, ca_path, chain_file, cert_file, key_file, cipher_list,
                   ip_address, port_number);
    }
    return (err);
done:
    cleanup_openssl();
    return (err);
}
