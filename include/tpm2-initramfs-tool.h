/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright 2018, Fraunhofer SIT
 * Copyright 2018, Jonas Witschel
 * Copyright © 2019 Canonical Ltd.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 or 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authored by: Tim Chen <tim.chen119@canonical.com>
 *
 */
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>

#define SECRETLEN 128
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define SECRETLEN_STR STR(SECRETLEN)

/* Trusted Platform Module Library Part 2: Structures,
 * Revision 01.38, Section 10.6.1.
 * Default PCRs list for pcrSelect: PCR 7
 */
#define DEFAULT_PCRS (0b000000000000000010000000)

/* Default bank hash algorithm: TPM2_ALG_SHA256 */
#define DEFAULT_BANKS (0b10)

#define TPM2_BANK_SHA1 (1 << 0)
#define TPM2_BANK_SHA256 (1 << 1)
#define TPM2_BANK_SHA384 (1 << 2)

/* TODO: document templates, algorithms and object attributes */
#define TPM2B_PUBLIC_PRIMARY_TEMPLATE                                          \
    {                                                                          \
        .size = 0, .publicArea = {                                      \
            .type = TPM2_ALG_ECC,                                       \
            .nameAlg = TPM2_ALG_SHA256,                                 \
            .objectAttributes =                                         \
                (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |    \
                 TPMA_OBJECT_DECRYPT | TPMA_OBJECT_NODA |               \
                 TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |       \
                 TPMA_OBJECT_SENSITIVEDATAORIGIN),                      \
            .authPolicy =                                               \
                {                                                       \
                    .size = 0,                                          \
                },                                                      \
            .parameters.eccDetail =                                     \
                {                                                       \
                    .symmetric =                                        \
                        {                                               \
                            .algorithm = TPM2_ALG_AES,                  \
                            .keyBits.aes = 128,                         \
                            .mode.aes = TPM2_ALG_CFB,                   \
                        },                                              \
                    .scheme = {.scheme = TPM2_ALG_NULL, .details = {}}, \
                    .curveID = TPM2_ECC_NIST_P256,                      \
                    .kdf = {.scheme = TPM2_ALG_NULL, .details = {}},    \
                },                                                      \
            .unique.ecc = {.x.size = 0, .y.size = 0}                    \
        }      \
    }

#define TPM2B_PUBLIC_KEY_TEMPLATE_UNSEAL                                         \
    {                                                                            \
        .size = 0, .publicArea = {                                             \
            .type = TPM2_ALG_KEYEDHASH,                                        \
            .nameAlg = TPM2_ALG_SHA256,                                        \
            .objectAttributes =                                                \
                (TPMA_OBJECT_FIXEDTPM |          \
                 TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_NODA),                  \
            .authPolicy = {.size = 0, .buffer = {0}},                          \
            .parameters.keyedHashDetail                                        \
                .scheme = {.scheme = TPM2_ALG_NULL,                            \
                           .details = {.hmac = {.hashAlg = TPM2_ALG_SHA256}}}, \
            .unique.keyedHash =                                                \
                {                                                              \
                    .size = 0,                                                 \
                    .buffer = {0},                                             \
                },                                                             \
        } \
    }

#define TPM2B_SENSITIVE_CREATE_TEMPLATE                                        \
    { .size = 0,                                                               \
      .sensitive = {                                                           \
              .userAuth = { .size = 0, .buffer = { 0 } },                      \
              .data = { .size = 0, .buffer = { 0 } },                          \
      } };

#define VERB(...)                                                              \
    if (opt.verbose)                                                           \
    fprintf(stderr, __VA_ARGS__)
#define ERR(...) fprintf(stderr, __VA_ARGS__)

#define chkrc(rc, cmd)                                                         \
    if (rc != TSS2_RC_SUCCESS) {                                               \
        ERR("ERROR in %s (%s:%i): 0x%08x\n", __func__, __FILE__, __LINE__,     \
            rc);                                                               \
        cmd;                                                                   \
    }

#define TPM2_INITRAMFS_TOOL_ENV_TCTI "TPM2_INITRAMFS_TOOL_TCTI"
#define TSS2_TCTI_SO_FORMAT "libtss2-tcti-%s.so.0"

extern TPM2B_PUBLIC primaryPublic;
extern TPM2B_SENSITIVE_CREATE primarySensitive;
extern TPM2B_DATA allOutsideInfo;
extern TPML_PCR_SELECTION allCreationPCR;

extern const char *help;
extern const char *optstr;
extern const struct option long_options[];

struct {
    enum { CMD_NONE, CMD_SEAL, CMD_UNSEAL } cmd;
    char *data;
    uint32_t persistent;
    int banks;
    int pcrs;
    char *tcti;
    int verbose;
} opt;

struct {
    void *dlhandle;
    TSS2_TCTI_CONTEXT *context;
} tcti;

void tcti_finalize();
int tcti_init(char *str, TSS2_TCTI_CONTEXT **context);
int pcr_unseal(uint32_t pcrs, uint32_t banks, uint32_t persistent, TSS2_TCTI_CONTEXT *tcti_context);
int pcr_seal(const char *data, uint32_t pcrs, uint32_t banks, uint32_t persistent, TSS2_TCTI_CONTEXT *tcti_context);
int parse_opts(int argc, char **argv);
char *base32enc(const uint8_t *in, size_t in_size);
