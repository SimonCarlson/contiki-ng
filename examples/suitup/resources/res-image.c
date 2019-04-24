#include <stdlib.h>
#include <string.h>
#include "coap-engine.h"
#include "opt-cose.h"

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

static void res_image_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

/*
 * A handler function named [resource name]_handler must be implemented for each RESOURCE.
 * A buffer for the response payload is provided through the buffer pointer. Simple resources can ignore
 * preferred_size and offset, but must respect the REST_MAX_CHUNK_SIZE limit for the buffer.
 * If a smaller block size is requested for CoAP, the REST framework automatically splits the data.
 */
RESOURCE(res_image,
         "title=\"Update image",
         res_image_handler,
         NULL,
         NULL,
         NULL);

#define CHUNKS_TOTAL 600000
#define SUITUP_COOJA

#define PRINTF_HEX(data, len) 	oscoap_printf_hex(data, len)
void oscoap_printf_hex(unsigned char*, unsigned int);

char *message = "-----BEGIN CERTIFICATE-----\n"
"MIIB2zCCAYKgAwIBAgIUJsaFHt1DXPxkxCchzB6a2kROqZwwCgYIKoZIzj0EAwIw\n"
"RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu\n"
"dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xOTAzMjYxMjMzMDhaFw0yMDAzMjUx\n"
"MjMzMDhaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD\n"
"VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwVjAQBgcqhkjOPQIBBgUrgQQA\n"
"CgNCAARpcQ0ZoXjob3wJcqo7Lr4z/+hE1GzEnHOY7ZOYSHZYyhPZl4qdRZfVBfs2\n"
"Jr6mvGh5bzJ/MgJNaQwjSii88zyco1MwUTAdBgNVHQ4EFgQUjNG0dbntVPQhBsZx\n"
"4zmtlcO4o4gwHwYDVR0jBBgwFoAUjNG0dbntVPQhBsZx4zmtlcO4o4gwDwYDVR0T\n"
"AQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBGoymLDOS+4FKPPy8+S8I7Bhz6\n"
"w1XvfvyW7+6jK9r/MQIgMK+T3BlnRHqcubSJFDek8SNj4ZyDXz8OCmYS92ehaFQ=\n"
"-----END CERTIFICATE-----\n";



static void
res_image_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  PRINTF("IMAGE RESOURCE\n");
  uint8_t data[32];
  opt_cose_encrypt_t cose;
  uint8_t cose_buffer = 0;
  char *aad = "0011bbcc22dd44ee55ff660077";
  uint8_t nonce[7] = {0, 1, 2, 3, 4, 5, 6};	// Hard coded nonce for example
  uint8_t key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  int32_t strpos = 0;
  static int block = 0;
  
  //printf("OFFSET: %d\n", *offset);
  if(*offset >= CHUNKS_TOTAL) {
    coap_set_status_code(response, BAD_OPTION_4_02);
    const char *error_msg = "BlockOutOfScope";
    coap_set_payload(response, error_msg, strlen(error_msg));
    return;
  }

  printf("OFFSET: %ld\n", *offset);
  //int length = strlen(message) - *offset < preferred_size - 8 ? strlen(message) -
  //*offset : preferred_size - 8;
  int length = 24;
  printf("length: %d\n", length);
  memcpy(data, message + *offset - 8 * block, length);
  data[length] = '\0';
  printf("Data plaintext: ");
  for(int i = 0; i < length; i++) {
    printf("%c", data[i]);
  }
  printf("\n");

  uint8_t ciphertext_buffer[length + 8]; // +8 för tag-len
  
  OPT_COSE_Init(&cose);
  OPT_COSE_SetAlg(&cose, COSE_Algorithm_AES_CCM_64_64_128);
  OPT_COSE_SetNonce(&cose, nonce, 7);
  OPT_COSE_SetContent(&cose, (uint8_t *)data, length);
  OPT_COSE_SetCiphertextBuffer(&cose, ciphertext_buffer, length + 8);
  OPT_COSE_SetAAD(&cose, (uint8_t *)aad, strlen(aad));
  printf("Encrypting image data\n");
  OPT_COSE_Encrypt(&cose, key, 16);
  printf("Encoding image data\n");
  OPT_COSE_Encode(&cose, &cose_buffer);
  //memcpy(data, cose.ciphertext, cose.ciphertext_len);
  printf("Ciphertext: ");
  PRINTF_HEX(cose.ciphertext, cose.ciphertext_len);
  printf("\n ciphertext len: %d\n", cose.ciphertext_len);

  // TODO: Why does this prevent stack smashing?? What is even happening to the stack
  //printf("DATA LEN: %d\n", strlen((char *)data));

  
  static int end = 0;
  printf("Remaining: %ld\n", strlen(message) - (*offset - 8 * block));
  if(strlen(message) - (*offset - 8 * block) >= 32) {
    //strncpy((char *)buffer, manifest + *offset, preferred_size);
    memcpy((char *)buffer, (char *)cose.ciphertext, 32);
    printf("Copy done\n");
  } else {
    //strncpy((char *)buffer, manifest + *offset, *offset - strlen(manifest));  
    //printf("LAST COPY: %d bytes\n", cose.ciphertext_len - *offset);
    printf("Last pass, copying %ld bytes\n", strlen(message) - (*offset - 8 * block));
    memcpy((char *)buffer, (char *)cose.ciphertext, 32);
    printf("Setting end to 1\n");
    end = 1;
  }
  
  block++;
  strpos += length + 8;
  
  if(strpos > preferred_size) {
    strpos = preferred_size;
  }
  
  if(*offset + (int32_t)strpos > CHUNKS_TOTAL) {
    strpos = CHUNKS_TOTAL - *offset;
  }

  coap_set_payload(response, buffer, strpos);
  // Update offset for next pass
  *offset += strpos - 8;
  //printf("FEOF: %d\n", feof(fd));
  // End block transmission if exceeding some limit or EOF found in manifest file
  if(*offset >= CHUNKS_TOTAL || end == 1){// || feof(fd)) {
    // End of block transfer
    printf("END\n");
    *offset = -1;
    end = 0;
    block = 0;
  }
}
