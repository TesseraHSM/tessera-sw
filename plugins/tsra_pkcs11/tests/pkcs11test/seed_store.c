// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Seeds a file object store for the conformance gate's second run (run.sh):
 * a public and a private token data object and a public token AES key, so the
 * tests that search and list objects meet a store that is not empty. The key
 * is public so a search finds it in every process: a private object is sealed
 * with a device key, and whether another process unmasks it depends on the
 * device's history.
 *
 *   seed_store <module.so> <pin>
 *
 * The module takes TSRA_PKCS11_PERSIST and TSRA_PKCS11_STORE_DIR from the
 * environment, as in every process that loads it.
 */

#include "tsra_pkcs11_compat.h"

#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define P11_COUNT(a) (sizeof(a) / sizeof((a)[0]))

/* Run one PKCS#11 call; on failure name it and stop seeding. */
#define P11_SEED(call)                                                                             \
    do                                                                                             \
    {                                                                                              \
        rv = (call);                                                                               \
        if (rv != CKR_OK)                                                                          \
        {                                                                                          \
            fprintf(stderr, "seed_store: %s: 0x%lx\n", #call, (unsigned long)rv);                  \
            goto cleanup;                                                                          \
        }                                                                                          \
    } while (0)

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "usage: %s <module.so> <pin>\n", argv[0]);
        return 2;
    }
    void *dl = dlopen(argv[1], RTLD_NOW);
    if (dl == NULL)
    {
        fprintf(stderr, "seed_store: %s\n", dlerror());
        return 1;
    }
    CK_C_GetFunctionList get_list = (CK_C_GetFunctionList)dlsym(dl, "C_GetFunctionList");
    CK_FUNCTION_LIST_PTR p11 = NULL;
    if ((get_list == NULL) || (get_list(&p11) != CKR_OK))
    {
        fprintf(stderr, "seed_store: no function list in %s\n", argv[1]);
        dlclose(dl);
        return 1;
    }

    CK_RV rv = CKR_OK;
    bool initialized = false;
    CK_SESSION_HANDLE s = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_OBJECT_CLASS data = CKO_DATA;
    CK_BYTE value[] = "seeded public value";
    CK_BYTE private_value[] = "seeded private value";
    char public_label[] = "seed-public-data";
    char private_label[] = "seed-private-data";
    char key_label[] = "seed-token-key";
    CK_ULONG key_len = 32;
    CK_MECHANISM keygen = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_ATTRIBUTE public_data[] = {
        { CKA_CLASS, &data, sizeof(data) },
        { CKA_TOKEN, &yes, sizeof(yes) },
        { CKA_PRIVATE, &no, sizeof(no) },
        { CKA_LABEL, public_label, sizeof(public_label) - 1 },
        { CKA_VALUE, value, sizeof(value) - 1 },
    };
    CK_ATTRIBUTE private_data[] = {
        { CKA_CLASS, &data, sizeof(data) },
        { CKA_TOKEN, &yes, sizeof(yes) },
        { CKA_PRIVATE, &yes, sizeof(yes) },
        { CKA_LABEL, private_label, sizeof(private_label) - 1 },
        { CKA_VALUE, private_value, sizeof(private_value) - 1 },
    };
    CK_ATTRIBUTE token_key[] = {
        { CKA_TOKEN, &yes, sizeof(yes) },
        { CKA_PRIVATE, &no, sizeof(no) },
        { CKA_VALUE_LEN, &key_len, sizeof(key_len) },
        { CKA_LABEL, key_label, sizeof(key_label) - 1 },
    };

    P11_SEED(p11->C_Initialize(NULL));
    initialized = true;
    P11_SEED(p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &s));
    P11_SEED(p11->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)argv[2], (CK_ULONG)strlen(argv[2])));
    P11_SEED(p11->C_CreateObject(s, public_data, P11_COUNT(public_data), &h));
    P11_SEED(p11->C_CreateObject(s, private_data, P11_COUNT(private_data), &h));
    P11_SEED(p11->C_GenerateKey(s, &keygen, token_key, P11_COUNT(token_key), &h));

cleanup:
    if (initialized)
    {
        (void)p11->C_Finalize(NULL);
    }
    dlclose(dl);
    return (rv == CKR_OK) ? 0 : 1;
}
