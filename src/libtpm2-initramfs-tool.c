/* SPDX-License-Identifier: GPL-2.0-or-later */
/*******************************************************************************
 * Copyright 2018, Fraunhofer SIT
 * Copyright 2018, Jonas Witschel
 * All rights reserved.
 *******************************************************************************/
/*
 * Copyright © 2019 Canonical Ltd.
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
 
#include "tpm2-initramfs-tool.h"

TPM2B_PUBLIC primaryPublic = TPM2B_PUBLIC_PRIMARY_TEMPLATE;
TPM2B_SENSITIVE_CREATE primarySensitive = TPM2B_SENSITIVE_CREATE_TEMPLATE;

TPM2B_DATA allOutsideInfo = {
    .size = 0,
};
TPML_PCR_SELECTION allCreationPCR = { .count = 0 };

/* TODO: add -o for output file, -i for input file */
const char *help =
        "Usage: [options] {seal|unseal}\n"
        "Options:\n"
        "    -h, --help       print help\n"
        "    -D  --data       Seal provided data in the persistent object (max chars:" SECRETLEN_STR
        ")\n"
        "    -P  --persistent Persistent object address (default: TPM2_PERSISTENT_FIRST)\n"
        "    -b, --banks      Selected PCR banks (default: SHA256, comma for separated list)\n"
        "    -p, --pcrs       Selected PCR registers (default: 7, comma for separated list)\n"
        "    -T, --tcti       TCTI to use (e.g. device:/dev/tpm0)\n"
        "    -v, --verbose    print verbose messages\n"
        "\n";

const char *optstr = "hD:P:b:p:T:v";

const struct option long_options[] = {
    { "help", no_argument, 0, 'h' },
    { "data", required_argument, 0, 'D' },
    { "persistent", required_argument, 0, 'P' },
    { "banks", required_argument, 0, 'b' },
    { "pcrs", required_argument, 0, 'p' },
    { "tcti", required_argument, 0, 'T' },
    { "verbose", no_argument, 0, 'v' },
    { 0, 0, 0, 0 }
};

/** Function to generating base32 encoding string.
 *
 * This function generate the base32 encoding for input data.
 * @param[in] in the chracter array pointer to be encoded.
 * @param[in] in_size the size of the input data.
 * @retval the pointer of base32 encoding chracters array.
 */
char *base32enc(const uint8_t *in, size_t in_size)
{
    static unsigned char base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    size_t i = 0, j = 0;
    size_t out_size = ((in_size + 4) / 5) * 8;

    unsigned char *r = malloc(out_size + 1);
    if (!r)
        return NULL;

    while (1) {
        r[i++] = in[j] >> 3 & 0x1F;
        r[i++] = in[j] << 2 & 0x1F;
        if (++j >= in_size)
            break;
        else
            i--;
        r[i++] |= in[j] >> 6 & 0x1F;
        r[i++] = in[j] >> 1 & 0x1F;
        r[i++] = in[j] << 4 & 0x1F;
        if (++j >= in_size)
            break;
        else
            i--;
        r[i++] |= in[j] >> 4 & 0x1F;
        r[i++] = in[j] << 1 & 0x1F;
        if (++j >= in_size)
            break;
        else
            i--;
        r[i++] |= in[j] >> 7 & 0x1F;
        r[i++] = in[j] >> 2 & 0x1F;
        r[i++] = in[j] << 3 & 0x1F;
        if (++j >= in_size)
            break;
        else
            i--;
        r[i++] |= in[j] >> 5 & 0x1F;
        r[i++] = in[j] & 0x1F;
        if (++j >= in_size)
            break;
    }
    for (j = 0; j < i; j++) {
        r[j] = base32[r[j]];
    }
    while (i < out_size) {
        r[i++] = '=';
    }
    r[i] = 0;
    return (char *)r;
}

/** Function to setup pcrSelections.
 *
 * This function setup PCRs selection list and bank hash algorithm.
 * @param[in] pcrs PCRs the key should be sealed against.
 * @param[in] banks PCR banks the key should be sealed against.
 * @param[in,out] pcrsel PCRs selection list.
 */
static void setup_pcr_selections(uint32_t *pcrs, uint32_t *banks,
                                 TPML_PCR_SELECTION *pcrsel)
{
    if (*pcrs == 0)
        *pcrs = DEFAULT_PCRS;

    if (*banks == 0)
        *banks = DEFAULT_BANKS;

    if ((*banks & TPM2_BANK_SHA1)) {
        pcrsel->pcrSelections[pcrsel->count].hash = TPM2_ALG_SHA1;
        pcrsel->count++;
    }
    if ((*banks & TPM2_BANK_SHA256)) {
        pcrsel->pcrSelections[pcrsel->count].hash = TPM2_ALG_SHA256;
        pcrsel->count++;
    }
    if ((*banks & TPM2_BANK_SHA384)) {
        pcrsel->pcrSelections[pcrsel->count].hash = TPM2_ALG_SHA384;
        pcrsel->count++;
    }

    for (size_t i = 0; i < pcrsel->count; i++) {
        pcrsel->pcrSelections[i].sizeofSelect = 3;
        pcrsel->pcrSelections[i].pcrSelect[0] = *pcrs & 0xff;
        pcrsel->pcrSelections[i].pcrSelect[1] = *pcrs >> 8 & 0xff;
        pcrsel->pcrSelections[i].pcrSelect[2] = *pcrs >> 16 & 0xff;
    }
}

/** Generate a key and seal as a persistent object with policy of PCRs.
 *
 * This function generate the key and seal it as a persistent object.
 * It output the key in base32 encoding to stdout.
 * @param[in] pcrs PCRs the key should be sealed against.
 * @param[in] banks PCR banks the key should be sealed against.
 * @param[in] persistent Persistent object address.
 * @param[in] tcti_context Optional TCTI context to select TPM to use.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 */
int pcr_seal(const char *data, uint32_t pcrs, uint32_t banks,
                    uint32_t persistent, TSS2_TCTI_CONTEXT *tcti_context)
{
    char *base32key = NULL;
    size_t base32keySize = 0;
    uint8_t *secret = NULL;
    size_t secretSize = 0;

    TPM2B_DIGEST *t = NULL, *policyDigest = NULL;
    ESYS_CONTEXT *ctx = NULL;
    ESYS_TR primary = ESYS_TR_NONE, session = ESYS_TR_NONE, key = ESYS_TR_NONE;
    TSS2_RC rc = -1;

    TPMT_SYM_DEF sym = { .algorithm = TPM2_ALG_AES,
                         .keyBits = { .aes = 128 },
                         .mode = { .aes = TPM2_ALG_CFB } };

    TPM2B_PUBLIC keyInPublicSeal = TPM2B_PUBLIC_KEY_TEMPLATE_UNSEAL;
    TPM2B_SENSITIVE_CREATE keySensitive = TPM2B_SENSITIVE_CREATE_TEMPLATE;
    TPM2B_PUBLIC *keyPublicHmac = NULL;
    TPM2B_PRIVATE *keyPrivateHmac = NULL;
    TPM2B_PUBLIC *keyPublicSeal = NULL;

    TPML_PCR_SELECTION pcrsel = { .count = 0 };

    TPM2_HANDLE permanentHandle =
            persistent ? persistent : (uint32_t)TPM2_PERSISTENT_FIRST;
    ESYS_TR persistentHandle1 = ESYS_TR_NONE;

    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA *fetchedData = NULL;
    int count;

    setup_pcr_selections(&pcrs, &banks, &pcrsel);

    secret = malloc(SECRETLEN + 1);
    if (!secret) {
        return -1;
    }
    memset(secret, 0, SECRETLEN + 1);

    rc = Esys_Initialize(&ctx, tcti_context, NULL);
    chkrc(rc, goto error);

    /* Check if we already seal the persistent object */
    rc = Esys_GetCapability(
            ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, TPM2_CAP_HANDLES,
            persistent ? persistent : (uint32_t)TPM2_PERSISTENT_FIRST,
            TPM2_MAX_CAP_HANDLES, &moreData, &fetchedData);
    chkrc(rc, goto error);
    count = fetchedData->data.handles.count;

    /* If persistent handle exists, try to remove the handle we plan to use */
    if (count > 0) {
        ESYS_TR outHandle;
        rc = Esys_TR_FromTPMPublic(
                ctx, persistent ? persistent : (uint32_t)TPM2_PERSISTENT_FIRST,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &outHandle);

        if (rc == TSS2_RC_SUCCESS) {
            VERB("Remove the persistent handle on 0x%x\n", persistent);
            rc = Esys_EvictControl(ctx, ESYS_TR_RH_OWNER, outHandle,
                                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                   permanentHandle, &persistentHandle1);
            chkrc(rc, Esys_FlushContext(ctx, outHandle); goto error);
        }
    }

    /* To seal the provided data */
    if (data) {
        if (strlen(data) > SECRETLEN)
            VERB("truncating provided data to " STR(SECRETLEN) " bytes \n");
        secretSize = strnlen(data, SECRETLEN);
        memcpy(&(secret)[0], &(data)[0], secretSize);
    } else {
        /* Generate the random string from TPM if no data provided */
        while (secretSize < SECRETLEN) {
            VERB("Calling Esys_GetRandom for %zu bytes\n",
                 SECRETLEN - secretSize);

            rc = Esys_GetRandom(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                SECRETLEN - secretSize, &t);
            chkrc(rc, goto error);

            base32key = base32enc(t->buffer, t->size);
            if (!base32key)
                goto error;

            base32keySize = strnlen(base32key, SECRETLEN - secretSize);

            memcpy(&(secret)[secretSize], &(base32key)[0], base32keySize);
            secretSize += base32keySize;
        }
    }

    /* Create Primary Object under the TPM_RH_OWNER hierarchy */
    rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                            ESYS_TR_NONE, ESYS_TR_NONE, &primarySensitive,
                            &primaryPublic, &allOutsideInfo, &allCreationPCR,
                            &primary, NULL, NULL, NULL, NULL);

    chkrc(rc, Esys_FlushContext(ctx, primary); goto error);

    /* Check PCRs */
    rc = Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            TPM2_CAP_PCRS, 0, TPM2_MAX_TPM_PROPERTIES,
                            &moreData, &fetchedData);
    chkrc(rc, goto error);
    count = fetchedData->data.assignedPCR.count;

    if (count == 0) {
        ERR("No active banks selected");
        return -1;
    }

    /* Setup PCR policy
     * 1. Start Trial Session
     * 2. Send appropriate TPM 2.0 session commands to update the digest
     * 3. Get final policy digest
     */
    rc = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_POLICY,
                               &sym, TPM2_ALG_SHA256, &session);
    chkrc(rc, goto error);

    rc = Esys_PolicyPCR(ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        NULL, &pcrsel);
    chkrc(rc, goto error);

    rc = Esys_PolicyGetDigest(ctx, session, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, &policyDigest);
    chkrc(rc, goto error);

    keyInPublicSeal.publicArea.authPolicy = *policyDigest;

    keySensitive.sensitive.data.size = secretSize;
    memcpy(&keySensitive.sensitive.data.buffer[0], &(secret)[0], secretSize);

    /* Create an object that can be loaded into TPM */
    rc = Esys_Create(ctx, primary, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                     &keySensitive, &keyInPublicSeal, &allOutsideInfo,
                     &allCreationPCR, &keyPrivateHmac, &keyPublicHmac, NULL,
                     NULL, NULL);
    chkrc(rc, goto error);

    rc = Esys_Load(ctx, primary, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   keyPrivateHmac, keyPublicHmac, &key);
    chkrc(rc, goto error);

    /* Save the object as persistent object */
    rc = Esys_EvictControl(ctx, ESYS_TR_RH_OWNER, key, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, permanentHandle,
                           &persistentHandle1);
    chkrc(rc, goto error);

    printf("%s", secret);

    rc = 0;

/* clean up */
error:

    if (base32key)
        free(base32key);
    if (secret)
        free(secret);
    if (t)
        free(t);
    if (policyDigest)
        free(policyDigest);

    if (primary != ESYS_TR_NONE)
        Esys_FlushContext(ctx, primary);
    if (session != ESYS_TR_NONE)
        Esys_FlushContext(ctx, session);
    if (key != ESYS_TR_NONE)
        Esys_FlushContext(ctx, key);
    if (ctx)
        Esys_Finalize(&ctx);

    if (keyPublicHmac)
        free(keyPublicHmac);
    if (keyPrivateHmac)
        free(keyPrivateHmac);
    if (keyPublicSeal)
        free(keyPublicSeal);
    if (fetchedData)
        free(fetchedData);

    return (int)rc;
}

/** Unseal a key with PCRs.
 *
 * This function will unseal the persistent object based on the PCRs.
 * It output the key in base32 encoding to stdout.
 * @param[in] pcrs PCRs the key should be sealed against.
 * @param[in] banks PCR banks the key should be sealed against.
 * @param[in] persistent Persistent object address.
 * @param[in] tcti_context Optional TCTI context to select TPM to use.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 */
int pcr_unseal(uint32_t pcrs, uint32_t banks, uint32_t persistent,
                      TSS2_TCTI_CONTEXT *tcti_context)
{
    ESYS_CONTEXT *ctx = NULL;
    ESYS_TR primary, session = ESYS_TR_NONE;
    TSS2_RC rc = -1;
    TPM2B_SENSITIVE_DATA *secret2b = NULL;

    TPMT_SYM_DEF sym = { .algorithm = TPM2_ALG_AES,
                         .keyBits = { .aes = 128 },
                         .mode = { .aes = TPM2_ALG_CFB } };

    TPML_PCR_SELECTION pcrsel = { .count = 0 };

    setup_pcr_selections(&pcrs, &banks, &pcrsel);

    rc = Esys_Initialize(&ctx, tcti_context, NULL);
    chkrc(rc, goto error);

    rc = Esys_TR_FromTPMPublic(
            ctx, persistent ? persistent : (uint32_t)TPM2_PERSISTENT_FIRST,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &primary);
    chkrc(rc, goto error);

    rc = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_POLICY,
                               &sym, TPM2_ALG_SHA256, &session);
    chkrc(rc, goto error);

    rc = Esys_PolicyPCR(ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        NULL, &pcrsel);
    chkrc(rc, goto error);

    rc = Esys_Unseal(ctx, primary, session, ESYS_TR_NONE, ESYS_TR_NONE,
                     &secret2b);
    chkrc(rc, goto error);

    printf("%s", secret2b->buffer);

    rc = 0;

/* clean up */
error:

    if (secret2b)
        free(secret2b);
    if (session != ESYS_TR_NONE)
        Esys_FlushContext(ctx, session);
    if (ctx)
        Esys_Finalize(&ctx);
    return (int)rc;
}

/** Parse TCTI options string.
 *
 * This function parse TCTI options string.
 * @param[in] str The TCTI options string.
 * @param[out] path the TCTI module library path.
 * @param[out] conf the TCTI configuration string.
 */
static void tcti_parse_string(char *str, char **path, char **conf)
{
    *path = str;
    char *split = strchr(str, ':');
    if (split == NULL) {
        *conf = NULL;
    } else {
        split[0] = '\0';
        *conf = &split[1];
    }
}

/** Load TCTI dynamic library.
 *
 * This function use dlopen to load TCTI library dynamicly.
 * @param[in] path the TCTI module library path.
 */
static void *tcti_dlopen(const char *path)
{
    void *dlhandle;

    dlhandle = dlopen(path, RTLD_LAZY);

    if (dlhandle) {
        return dlhandle;
    } else {
        /* Expand <tcti> to libtss2-tcti-<tcti>.so.0 */
        char *dlname;

        int size = snprintf(NULL, 0, TSS2_TCTI_SO_FORMAT, path);
        if (size <= 0) {
            ERR("Could not open TCTI %s.\n", path);
            return NULL;
        }

        dlname = malloc(size + 1);
        if (!dlname) {
            ERR("oom");
            return NULL;
        }

        snprintf(dlname, size + 1, TSS2_TCTI_SO_FORMAT, path);
        dlhandle = dlopen(dlname, RTLD_LAZY);
        free(dlname);
        return dlhandle;
    }
}

/** Initial TCTI context.
 *
 * This function will unseal the persistent object based on the PCRs.
 * @param[in] str The TCTI options string.
 * @param[out] context TCTI context to select TPM to use.
 * @retval 0 on success.
 * @retval 1 on undefined/general failure.
 */
int tcti_init(char *str, TSS2_TCTI_CONTEXT **context)
{
    *context = tcti.context = NULL;

    /* If no option is given, load from environment or use default TCTI */
    if (!str) {
        str = getenv(TPM2_INITRAMFS_TOOL_ENV_TCTI);
        if (!str) {
            return 0;
        }
    }

    char *path;
    char *conf;
    tcti_parse_string(str, &path, &conf);
    if (path[0] == '\0') {
        ERR("No TCTI given.\n");
        return 1;
    }

    tcti.dlhandle = tcti_dlopen(path);
    if (!tcti.dlhandle) {
        ERR("Could not open TCTI '%s'.\n", path);
        return 1;
    }

    TSS2_TCTI_INFO_FUNC infofn =
            (TSS2_TCTI_INFO_FUNC)dlsym(tcti.dlhandle, TSS2_TCTI_INFO_SYMBOL);
    if (!infofn) {
        dlclose(tcti.dlhandle);
        ERR("Symbol '%s' not found in library '%s'.\n", TSS2_TCTI_INFO_SYMBOL,
            path);
        return 1;
    }
    const TSS2_TCTI_INFO *info = infofn();
    const TSS2_TCTI_INIT_FUNC init = info->init;

    size_t context_size;
    if (init(NULL, &context_size, conf) != TPM2_RC_SUCCESS) {
        ERR("TCTI init routine failed.\n");
        goto err;
    }

    tcti.context = (TSS2_TCTI_CONTEXT *)malloc(context_size);
    if (!tcti.context) {
        ERR("oom");
        goto err;
    }
    if (init(tcti.context, &context_size, conf) != TPM2_RC_SUCCESS) {
        ERR("TCTI context creation failed.\n");
        goto err;
    }

    *context = tcti.context;
    return 0;

err:
    free(tcti.context);
    tcti.context = NULL;
    dlclose(tcti.dlhandle);
    tcti.dlhandle = NULL;
    return 1;
}

/* Finalize TCTI context */
void tcti_finalize()
{
    if (tcti.context) {
        Tss2_Tcti_Finalize(tcti.context);
        free(tcti.context);
        dlclose(tcti.dlhandle);
    }
}

/** Parse Banks argument.
 *
 * @param[in,out] str The argument string pointer to be parsed.
 * @param[in,out] banks Construct banks from the string arguments.
 * @retval 0 on success
 * @retval -1 on failure
 */
static int parse_banks(char *str, int *banks)
{
    char *token;
    char *saveptr;

    *banks = 0;

    token = strtok_r(str, ",", &saveptr);
    if (!token) {
        return -1;
    }
    while (token) {
        if (strcmp(token, "SHA1") == 0) {
            *banks |= TPM2_BANK_SHA1;
        } else if (strcmp(token, "SHA256") == 0) {
            *banks |= TPM2_BANK_SHA256;
        } else if (strcmp(token, "SHA384") == 0) {
            *banks |= TPM2_BANK_SHA384;
        } else {
            return -1;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    return 0;
}

/** Parse PCRs argument.
 *
 * @param[in,out] str The argument string pointer to be parsed.
 * @param[in,out] pcrs Construct pcrs from the string arguments.
 * @retval 0 on success
 * @retval -1 on failure
 */
static int parse_pcrs(char *str, int *pcrs)
{
    char *token;
    char *saveptr;
    char *endptr;
    long pcr;

    *pcrs = 0;

    token = strtok_r(str, ",", &saveptr);
    if (!token) {
        return -1;
    }
    while (token) {
        errno = 0;
        pcr = strtoul(token, &endptr, 0);
        if (errno || endptr == token || *endptr != '\0') {
            return -1;
        } else {
            *pcrs |= 1 << pcr;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    return 0;
}

/** Parse and set command line options.
 *
 * This function parses the command line options and sets the appropriate values
 * in the opt struct.
 * @param argc The argument count.
 * @param argv The arguments.
 * @retval 0 on success
 * @retval -1 on failure
 */
int parse_opts(int argc, char **argv)
{
    /* set the default values */
    opt.cmd = CMD_NONE;
    opt.data = NULL;
    opt.banks = 0;
    opt.pcrs = 0;
    opt.persistent = TPM2_PERSISTENT_FIRST;
    opt.verbose = 0;

    /* parse the options */
    int c;
    int opt_idx = 0;
    while (-1 !=
           (c = getopt_long(argc, argv, optstr, long_options, &opt_idx))) {
        switch (c) {
        case 'h':
            printf("%s", help);
            exit(0);
        case 'D':
            opt.data = optarg;
            break;
        case 'P':
            if (sscanf(optarg, "0x%x", &opt.persistent) != 1 &&
                sscanf(optarg, "%i", &opt.persistent) != 1) {
                opt.persistent = TPM2_PERSISTENT_FIRST;
            }
            if (opt.persistent < (uint32_t)TPM2_PERSISTENT_FIRST ||
                opt.persistent > (uint32_t)TPM2_PERSISTENT_LAST) {
                ERR("Error parsing persistent object address.\n");
            }
            break;
        case 'b':
            if (parse_banks(optarg, &opt.banks) != 0) {
                ERR("Error parsing banks.\n");
                return -1;
            }
            break;
        case 'p':
            if (parse_pcrs(optarg, &opt.pcrs) != 0) {
                ERR("Error parsing pcrs.\n");
                return -1;
            }
            break;
        case 'T':
            opt.tcti = optarg;
            break;
        case 'v':
            opt.verbose = 1;
            break;
        default:
            ERR("Unknown option at index %i.\n\n", opt_idx);
            ERR("%s", help);
            return -1;
        }
    }

    /* parse the non-option arguments */
    if (optind >= argc) {
        ERR("Missing command: seal, unseal.\n\n");
        ERR("%s", help);
        return -1;
    }
    if (!strcmp(argv[optind], "seal")) {
        opt.cmd = CMD_SEAL;
    } else if (!strcmp(argv[optind], "unseal")) {
        opt.cmd = CMD_UNSEAL;
    } else {
        ERR("Unknown command: seal, unseal.\n\n");
        ERR("%s", help);
        return -1;
    }
    optind++;

    if (optind < argc) {
        ERR("Unknown argument provided.\n\n");
        ERR("%s", help);
        return -1;
    }
    return 0;
}
