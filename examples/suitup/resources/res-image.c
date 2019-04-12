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

char *image = "This is a payload message! This is a payload message! This is a payload message! This is a payload message! This is a payload message!";

static void
res_image_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  PRINTF("IMAGE RESOURCE\n");
  int32_t strpos = 0;
  printf("OFFSET: %d\n", *offset);
  if(*offset >= CHUNKS_TOTAL) {
    printf("Bad option\n");
    coap_set_status_code(response, BAD_OPTION_4_02);
    const char *error_msg = "BlockOutOfScope";
    coap_set_payload(response, error_msg, strlen(error_msg));
    return;
  }

  static opt_cose_encrypt_t cose;
  uint8_t cose_buffer = 0;
  char *aad = "0011bbcc22dd44ee55ff660077";
  uint8_t nonce[7] = {0, 1, 2, 3, 4, 5, 6};	// Hard coded nonce for example
  uint8_t key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  static uint8_t ciphertext_buffer[704+8]; // +8 för tag-len

  static int transmit = 0;
  static int file_len;
  FILE *fd = fopen("/home/user/contiki-ng/examples/suitup/client-cert.pem", "rb");

  if(!transmit) {
    // TODO: Open file, read it entirely, COSE encrypt, stateful transfer of encrypted message
    fseek(fd, 0L, SEEK_END);
    file_len = ftell(fd);
    printf("FILE_LEN: %d\n", file_len);
    rewind(fd);

    char plaintext_buffer[file_len];
    fread(plaintext_buffer, 1, file_len, fd);

    OPT_COSE_Init(&cose);
	  OPT_COSE_SetAlg(&cose, COSE_Algorithm_AES_CCM_64_64_128);
	  OPT_COSE_SetNonce(&cose, nonce, 7);
	  OPT_COSE_SetContent(&cose, (uint8_t *)plaintext_buffer, file_len);
	  OPT_COSE_SetCiphertextBuffer(&cose, ciphertext_buffer, file_len + 8);
	  OPT_COSE_SetAAD(&cose, (uint8_t *)aad, strlen(aad));
	  OPT_COSE_Encrypt(&cose, key, 16);
	  OPT_COSE_Encode(&cose, &cose_buffer);

    transmit = 1;
  }

  printf("AFTER ENCRYPT\n");
  
  static int end = 0;
  if(*offset > cose.ciphertext_len) {
    //strncpy((char *)buffer, image + *offset, *offset - strlen(image));
    printf("LAST OFFSET: %d\n", *offset);
    //bytes = fread(buffer, 1, *offset - file_len, fd);
    memcpy((char *)buffer, (char *)cose.ciphertext + *offset, *offset - cose.ciphertext_len);
    end = 1;
  } else {
    //strncpy((char *)buffer, image + *offset, preferred_size);
    //bytes = fread(buffer, 1, preferred_size, fd);
    memcpy((char *)buffer, (char *)cose.ciphertext + *offset, preferred_size);
  }
  
  printf("BUFFER: %s\n", buffer);
  strpos += preferred_size;
  
  if(strpos > preferred_size) {
    strpos = preferred_size;
  }
  
  if(*offset + (int32_t)strpos > CHUNKS_TOTAL) {
    strpos = CHUNKS_TOTAL - *offset;
  }

  coap_set_payload(response, buffer, strpos);
  // Update offset for next pass
  *offset += strpos;
  //printf("FEOF: %d\n", feof(fd));
  // End block transmission if exceeding some limit or EOF found in image file
  if(*offset >= CHUNKS_TOTAL || end == 1){// || feof(fd)) {
    // End of block transfer
    printf("END: %d\n", *offset >= CHUNKS_TOTAL);
    *offset = -1;
    end = 0;
    transmit = 0;
  }
}
