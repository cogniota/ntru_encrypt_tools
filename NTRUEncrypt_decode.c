#include "NTRUEncrypt_general.h"

int main(int argc, char *argv[])
{
    uint8_t private_key[607];         /* sized for EES401EP2 */
    uint16_t private_key_len = 607;         /* no. of octets in private key */
    uint8_t *ciphertext;              /* sized fof EES401EP2 */
    uint16_t ciphertext_len;          /* no. of octets in ciphertext */
    uint8_t plaintext[60];               /* size of plaintext  */
    uint16_t plaintext_len;           /* no. of octets in plaintext */
    uint32_t rc;                      /* return code */
    bool error = FALSE;               /* records if error occurred */
    FILE *Handle=NULL;                /* File Handle for writing NTRU key to file */

    if(argc != 5 || strcmp(argv[1],"--key_name") || strcmp(argv[3],"--ciphertext_file"))
    {
      printf("(--key_name key_name --ciphertext_file ciphertext_file) format expected\n");
      return 1;
    }

    Handle = fopen(argv[4], "rb");  // Open the file in binary mode
    fseek(Handle, 0, SEEK_END);          // Jump to the end of the file
    ciphertext_len = ftell(Handle);             // Get the current byte offset in the file
    rewind(Handle);                      // Jump back to the beginning of the file

    ciphertext = (uint8_t *)malloc((ciphertext_len+1)*sizeof(uint8_t)); // Enough memory for file + \0
    fread(ciphertext, ciphertext_len, 1, Handle); // Read in the entire file
    fclose(Handle); // Close the file
    printf("ciphertext %s %d\n", ciphertext, ciphertext_len);

    Handle = fopen(argv[2], "rb");  // Open the file in binary mode
    fread(private_key, private_key_len, 1, Handle); // Read in the entire file
    fclose(Handle); // Close the file

    /* Get maximum plaintext length */
    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                  0, NULL,
                                  &plaintext_len, NULL);

    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                  ciphertext_len, ciphertext,
                                  &plaintext_len, plaintext);
    if(rc != NTRU_RESULT(NTRU_OK)) 
    {
    	printf("\n Err\n");
    	goto error; 
    }

    printf("\nplaintext\n");
    DumpHex(plaintext,plaintext_len);
    printf("\n%s %d\n", plaintext, plaintext_len);

    return 0;
    
    error:
    printf("Error (0x%x)\n", rc);
    return 1;
}      