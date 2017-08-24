#include "NTRUEncrypt_general.h"

/*
* This program gets 2 arguments : --key_name key_name.
* Generate pub and priv keys and save it to key_name(priv).
* key_name_pubkey.der (pub) in DER code.
*/
int
main(int argc, char **argv)
{
    uint8_t public_key[557];          /* sized for EES401EP2 */
    uint16_t public_key_len;          /* no. of octets in public key */
    uint8_t private_key[607];         /* sized for EES401EP2 */
    uint16_t private_key_len;         /* no. of octets in private key */
    uint16_t expected_private_key_len;
    uint16_t expected_encoded_public_key_len;
    uint16_t expected_encoded_private_key_len;
    uint8_t encoded_public_key[593];  /* sized for EES401EP2 */
    uint16_t encoded_public_key_len;  /* no. of octets in encoded public key */
    uint16_t encoded_private_key_len;  /* no. of octets in encoded private key */
    uint8_t ciphertext[552];          /* sized fof EES401EP2 */
    uint16_t ciphertext_len;          /* no. of octets in ciphertext */
    uint8_t plaintext[16];            /* size of AES-128 key */
    uint16_t plaintext_len;           /* no. of octets in plaintext */
    uint8_t *next = NULL;             /* points to next cert field to parse */
    uint32_t next_len;                /* no. of octets it next */
    DRBG_HANDLE drbg;                 /* handle for instantiated DRBG */
    uint32_t rc;                      /* return code */
    bool error = FALSE;               /* records if error occurred */
    FILE *Handle=NULL;                /* File Handle for writing NTRU key to file */

    char *key_name = NULL;
    char *pub_key_name = NULL;

    key_name = "ntru_key";

    if(argc != 3 || strcmp(argv[1], "--key_name"))
    {
		printf("(--key_name key_name ) format expected\n");
    	return 1;
    }

	key_name = argv[2];

    /* Instantiate a DRBG with 112-bit security strength for key generation
     * to match the security strength of the EES401EP2 parameter set.
     * Here we've chosen to use the personalization string.
     */
    rc = ntru_crypto_drbg_instantiate(112, pers_str, sizeof(pers_str),
                                      (ENTROPY_FN) &get_entropy, &drbg);
    if (rc != DRBG_OK)
        /* An error occurred during DRBG instantiation. */
        goto error;
    printf("DRBG at 112-bit security for key generation instantiated "
            "successfully.\n");


    /* Let's find out how large a buffer we need for the public and private
     * keys.
     */
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2, &public_key_len,
                                         NULL, &private_key_len, NULL);
    if (rc != NTRU_OK)
        /* An error occurred requesting the buffer sizes needed. */
        goto error;
    printf("Public-key buffer size required: %d octets.\n", public_key_len);
    printf("Private-key buffer size required: %d octets.\n", private_key_len);


    /* Now we could allocate a buffer of length public_key_len to hold the
     * public key, and a buffer of length private_key_len to hold the private
     * key, but in this example we already have them as local variables.
     */


    /* Generate a key pair for EES401EP2.
     * We must set the public-key length to the size of the buffer we have
     * for the public key, and similarly for the private-key length.
     * We've already done this by getting the sizes from the previous call
     * to ntru_crypto_ntru_encrypt_keygen() above.
     */
    expected_private_key_len=private_key_len;
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2, &public_key_len,
                                         public_key, &private_key_len,
                                         private_key);
    if (rc != NTRU_OK)
        /* An error occurred during key generation. */
        error = TRUE;
    if (expected_private_key_len!=private_key_len)
    {
      fprintf(stderr,"private-key-length is different than expected\n");
      error = TRUE;
    }
    printf("Key-pair for NTRU_EES401EP2 generated successfully.\n");


    /* Uninstantiate the DRBG. */
    rc = ntru_crypto_drbg_uninstantiate(drbg);
    if ((rc != DRBG_OK) || error)
        /* An error occurred uninstantiating the DRBG, or generating keys. */
        goto error;
    printf("Key-generation DRBG uninstantiated successfully.\n");

    /* Writing both private key and public key to files */  
    Handle=fopen(key_name,"wb");
    if(Handle!=NULL)
    {
      printf("Writing private key to %s\n", key_name);
      fwrite(private_key,private_key_len,1,Handle);
      fclose(Handle);
    }

    // Handle=fopen("sample-ntru-pubkey.raw","wb");
    // if(Handle!=NULL)
    // {
    //   printf("Writing public key to ntru-pubkey.raw\n");
    //   fwrite(public_key,public_key_len,1,Handle);
    //   fclose(Handle);
    // }

    /* Let's find out how large a buffer we need for holding a DER-encoding
     * of the public key.
     */
    rc = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
            public_key_len, public_key, &encoded_public_key_len, NULL);
    if (rc != NTRU_OK)
        /* An error occurred requesting the buffer size needed. */
        goto error;
    printf("DER-encoded public-key buffer size required: %d octets.\n",
            encoded_public_key_len);


    /* Now we could allocate a buffer of length encoded_public_key_len to
     * hold the encoded public key, but in this example we already have it
     * as a local variable.
     */
    expected_encoded_public_key_len=encoded_public_key_len;

    /* DER-encode the public key for inclusion in a certificate.
     * This creates a SubjectPublicKeyInfo field from a public key.
     * We must set the encoded public-key length to the size of the buffer
     * we have for the encoded public key.
     * We've already done this by getting the size from the previous call
     * to ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKey() above.
     */
    rc = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
            public_key_len, public_key, &encoded_public_key_len,
            encoded_public_key);

    if (expected_encoded_public_key_len!=encoded_public_key_len)
    {
      fprintf(stderr,"encoded_public_key_len is different than expected\n");
      error = TRUE;
    }

    printf("Public key DER-encoded for SubjectPublicKeyInfo successfully.\n");

    printf("DER encoded public key in hex (with length %d):\n",encoded_public_key_len);
    DumpHex(encoded_public_key,encoded_public_key_len);

    printf("encoded public key %s\n", encoded_public_key);

    pub_key_name = malloc(strlen(argv[2]) * sizeof(char));
    strcpy(pub_key_name,argv[2]);
    strcat(pub_key_name,"_pubkey.der");

    Handle=fopen(pub_key_name,"wb");
    if(Handle!=NULL)
    {
      printf("Writing DER encoded public key to %s\n", pub_key_name);
      fwrite(encoded_public_key,encoded_public_key_len,1,Handle);
      fclose(Handle);
    }

    return 0;

    error:
    printf("Error (0x%x)\n", rc);
    return 1;
}    