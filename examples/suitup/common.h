#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

// https://www.bmt-online.org/geekisms/RSA_verify
int 
sign_data(
        const char *keyfile,
        const void *buf,    /* input data: byte array */
        size_t buf_len, 
        void **out_sig,     /* output signature block, allocated in the function */
        size_t *out_sig_len) {

    unsigned char *sig = NULL;
    unsigned int sig_len = 0;
    int status = EXIT_SUCCESS;
    int rc = 1;

    FILE *fd;
    fd = fopen(keyfile, "rb"); 
    RSA *r = PEM_read_RSAPrivateKey(fd, NULL, NULL, NULL);
    fclose(fd);

    SHA_CTX sha_ctx = { 0 };
    unsigned char digest[SHA_DIGEST_LENGTH];

    rc = SHA1_Init(&sha_ctx);
    if (1 != rc) { printf("SHA init failed.\n"); status = EXIT_FAILURE; goto end; }
    rc = SHA1_Update(&sha_ctx, buf, buf_len);
    if (1 != rc) { printf("SHA update failed.\n"); status = EXIT_FAILURE; goto end; }
    rc = SHA1_Final(digest, &sha_ctx);
    if (1 != rc) { printf("SHA final failed.\n"); status = EXIT_FAILURE; goto end; }
    sig = malloc(RSA_size(r));
    if (NULL == sig) { printf("Malloc failed.\n"); status = EXIT_FAILURE; goto end; }
    rc = RSA_sign(NID_sha1, digest, sizeof digest, sig, &sig_len, r);
    if (1 != rc) { printf("RSA sign failed.\n"); status = EXIT_FAILURE; goto end; }

    *out_sig = sig;
    *out_sig_len = sig_len;

end:
    if (NULL != r) RSA_free(r);
    if (EXIT_SUCCESS != status) free(sig); /* in case of failure: free allocated resource */
    if (1 != rc) fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));

    return status;
}

int 
verify_data(
        const char *keyfile,
        const void *sig,
        size_t sig_len,
        const void *buf,        
        size_t buf_len) {

    int status = EXIT_SUCCESS; 
    int rc = 1; /* OpenSSL return code */ 

    EVP_PKEY *k = NULL;

    FILE *fd;
    fd = fopen(keyfile, "rb"); 
    X509 *c = PEM_read_X509(fd, NULL, NULL, NULL);
    fclose(fd);
    
    SHA_CTX sha_ctx = { 0 };
    unsigned char digest[SHA_DIGEST_LENGTH];

    rc = SHA1_Init(&sha_ctx);
    if (1 != rc) { printf("SHA init failed.\n"); status = EXIT_FAILURE; goto end; }
    rc = SHA1_Update(&sha_ctx, buf, buf_len);
    if (1 != rc) { printf("SHA update failed.\n"); status = EXIT_FAILURE; goto end; }
    rc = SHA1_Final(digest, &sha_ctx);
    if (1 != rc) { printf("SHA final failed.\n"); status = EXIT_FAILURE; goto end; }
    k = X509_get_pubkey(c);
    if (1 != rc) { printf("X509 get failed.\n"); status = EXIT_FAILURE; goto end; }
    rc = RSA_verify(NID_sha1, digest, sizeof digest, sig, sig_len, EVP_PKEY_get1_RSA(k));
    if (1 != rc) { printf("RSA verify failed.\n"); status = EXIT_FAILURE; goto end; }

end:
    if (NULL != k) EVP_PKEY_free(k);
    return status;
}

// https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
void 
hex_dump (void *addr, size_t len) {
    unsigned char buff[17];
    unsigned char *pc = (unsigned char *) addr;
    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %li\n", len);
        return;
    }
    // Process every byte in the data.
    int i;
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).
        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }
        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);
        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }
    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}
