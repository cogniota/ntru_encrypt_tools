#include "NTRUEncrypt_general.h"

int main(int argc, char *argv[])
{
	uint8_t public_key[557];          /* sized for EES401EP2 */
	uint16_t public_key_len;          /* no. of octets in public key */
	uint8_t encoded_public_key[593];  /* sized for EES401EP2 */
	uint16_t encoded_public_key_len = 593;  /* no. of octets in encoded public key */
	uint8_t ciphertext[552];          /* sized fof EES401EP2 */
	uint16_t ciphertext_len;          /* no. of octets in ciphertext */
	uint8_t *next = NULL;             /* points to next cert field to parse */
	uint32_t next_len;                /* no. of octets it next */
	DRBG_HANDLE drbg;                 /* handle for instantiated DRBG */
	uint32_t rc;                      /* return code */
	bool error = FALSE;               /* records if error occurred */
	FILE *Handle=NULL;                /* File Handle for writing NTRU key to file */

	uint8_t text_to_encode[60];

	char *key_name = NULL;

	if(argc != 7 || strcmp(argv[1],"--key_name")
		|| strcmp(argv[3],"--text_to_encode") || strlen(argv[4]) > 60 
		|| (strcmp(argv[5], "--ciphertext_file" ) && strcmp(argv[5], "--return" ) ))
	{
		printf("(--key_name key_name --text_to_encode text_to_encode[l] [--ciphertext_file ciphertext_file | --return any_word],\n where l <= 60) format expected\n");
		return 1;
	}

	key_name = malloc(strlen(argv[2]) * sizeof(char));

	strcpy(key_name,argv[2]);
	strcat(key_name,"_pubkey.der");
	strcpy(text_to_encode,argv[4]);

	Handle=fopen(key_name,"rb");
	if(Handle!=NULL)
	{
	  printf("Reading public key from %s\n",key_name);
	  fread(encoded_public_key,1,593,Handle);
	  fclose(Handle);
	}

	DumpHex(encoded_public_key,593);

	/* Now suppose we are parsing a certificate so we can use the
	 * public key it contains, and the next field is the SubjectPublicKeyInfo
	 * field.  This is indicated by the "next" pointer.  We'll decode this
	 * field to retrieve the public key so we can use it for encryption.
	 * First let's find out how large a buffer we need for holding the
	 * DER-decoded public key.
	 */
	next = encoded_public_key;          /* the next pointer will be pointing
	                                       to the SubjectPublicKeyInfo field */
	next_len = encoded_public_key_len;
	rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(next,
	        &public_key_len, NULL, &next, &next_len);
	if (rc != NTRU_OK)
	    /* An error occurred requesting the buffer size needed. */
	    goto error;
	printf("Public-key buffer size required: %d octets.\n", public_key_len);


	/* Now we could allocate a buffer of length public_key_len to hold the
	 * decoded public key, but in this example we already have it as a
	 * local variable.
	 */


	/* Decode the SubjectPublicKeyInfo field.  Note that if successful,
	 * the "next" pointer will now point to the next field following
	 * the SubjectPublicKeyInfo field, or NULL if we've exhausted the
	 * buffer.
	 */
	rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(next,
	        &public_key_len, public_key, &next, &next_len);
	if (rc != NTRU_OK)
	    /* An error occurred decoding the SubjectPublicKeyInfo field.
	     * This could indicate that the field is not a valid encoding
	     * of an NTRUEncrypt public key.
	     */
	    goto error;
	printf("Public key decoded from SubjectPublicKeyInfo successfully.\n");


	rc = ntru_crypto_drbg_instantiate(112, NULL, 0, (ENTROPY_FN) &get_entropy, &drbg);
	if (rc != DRBG_OK)
	    /* An error occurred during DRBG instantiation. */
	    goto error;
	printf("DRBG at 112-bit security for encryption instantiated "
	        "successfully.\n");

	/* Get the ciphertext buffer size */
	rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
	                        0, NULL,
	                        &ciphertext_len, NULL);
	if(rc != NTRU_RESULT(NTRU_OK)) 
	{
	  goto error; 
	}

	/* Allocate memory for ciphertext */
	// ...
	/* Perform the encryption */
	rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
	                        sizeof(text_to_encode), text_to_encode,
	                        &ciphertext_len, ciphertext);
	if(rc != NTRU_RESULT(NTRU_OK)) 
	{
	  goto error; 
	}

	printf("public_key_len %d\n", public_key_len);
	printf("public_key%s\n", public_key);
	printf("ciphertext%s\n", ciphertext);
	printf("ciphertext_len%d\n", ciphertext_len);

	if(!strcmp(argv[5], "--return" ))
	{
		ciphertext; // TODO return text 
		return 0;
	}

	Handle=fopen(argv[6],"wb");
	if(Handle!=NULL)
	{
	  printf("Writing ciphertext to ciphertext file\n");
	  fwrite(ciphertext,ciphertext_len,1,Handle);
	  fclose(Handle);
	}

	return 0;

	error:
	printf("Error (0x%x)\n", rc);
	return 1;

}    