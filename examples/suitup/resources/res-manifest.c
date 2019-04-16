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

#define PRINTF_HEX(data, len) 	oscoap_printf_hex(data, len)
void oscoap_printf_hex(unsigned char*, unsigned int);

static void res_manifest_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

/*
 * A handler function named [resource name]_handler must be implemented for each RESOURCE.
 * A buffer for the response payload is provided through the buffer pointer. Simple resources can ignore
 * preferred_size and offset, but must respect the REST_MAX_CHUNK_SIZE limit for the buffer.
 * If a smaller block size is requested for CoAP, the REST framework automatically Fsplits the data.
 */
RESOURCE(res_manifest,
         "title=\"Update manifest",
         res_manifest_handler,
         NULL,
         NULL,
         NULL);
  
#define CHUNKS_TOTAL 2050 // How to determine? Size of file? 
static char *manifest= "{\"0\": 1, \"1\": \"1553762654\", \"2\": [{\"0\": 0, \"1\": \"4be0643f-1d98-573b-97cd-ca98a65347dd\"}, {\"0\": 1, \"1\": \"18ce9adf-9d2e-57a3-9374-076282f3d95b\"}], \"3\": [], \"4\": 0, \"5\": {\"0\": 1, \"1\": 184380, \"2\": 0, \"3\": [{\"0\": \"update/image\", \"1\": \"ac526296b4f53eed4ab337f158afc12755bd046d0982b4fa227ee09897bc32ef\"}]}, \"6\": [], \"7\": [], \"8\": []}";

static void
res_manifest_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  static int transmit = 0;
  static opt_cose_encrypt_t cose;
  uint8_t data[335];
  uint8_t cose_buffer = 0;
  char *aad = "0011bbcc22dd44ee55ff660077";
  uint8_t nonce[7] = {0, 1, 2, 3, 4, 5, 6};	// Hard coded nonce for example
  uint8_t key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  static uint8_t ciphertext_buffer[335]; // +8 för tag-len
  PRINTF("MANIFEST RESOURCE\n");
  int32_t strpos = 0;

  printf("OFFSET: %d\n", *offset);
  if(*offset >= CHUNKS_TOTAL) {
    coap_set_status_code(response, BAD_OPTION_4_02);
    const char *error_msg = "BlockOutOfScope";
    coap_set_payload(response, error_msg, strlen(error_msg));
    return;
  }

  printf("STRLEN: %d\n", strlen(manifest));
  if(!transmit) {
	  OPT_COSE_Init(&cose);
	  OPT_COSE_SetAlg(&cose, COSE_Algorithm_AES_CCM_64_64_128);
	  OPT_COSE_SetNonce(&cose, nonce, 7);
	  OPT_COSE_SetContent(&cose, (uint8_t *)manifest, strlen(manifest));
	  OPT_COSE_SetCiphertextBuffer(&cose, ciphertext_buffer, 335);
	  OPT_COSE_SetAAD(&cose, (uint8_t *)aad, strlen(aad));
	  OPT_COSE_Encrypt(&cose, key, 16);
	  OPT_COSE_Encode(&cose, &cose_buffer);
    //memcpy(data, cose.ciphertext, cose.ciphertext_len);
    transmit = 1;
  }

  

  //printf("Before strncpy\n");
  //strncpy(data, (char *)cose.ciphertext, 2);
  //printf("DATA: \n");
  //PRINTF_HEX((uint8_t *)data, 335);
  printf("DATA LEN: %d\n", strlen((char *)data));

  // Generate data; copy manifest chunk by chunk into buffer, update strpos with bytes
  // copied
  //FILE *fd = fopen("/home/rzmd/Documents/git-repos/contiki-ng/examples/suitup/example-manifest.json", "r");
  //int bytes;
  //fseek(fd, *offset, SEEK_CUR);
  //bytes = fread((char*)buffer, 1, preferred_size, fd);
  
  printf("COSE: %d OFFSET: %d\n", cose.ciphertext_len, *offset);
  static int end = 0;
  if(cose.ciphertext_len - *offset > 32) {
    //strncpy((char *)buffer, manifest + *offset, preferred_size);
    memcpy((char *)buffer, (char *)cose.ciphertext + *offset, preferred_size);
    printf("SENDING: ");
    PRINTF_HEX(buffer, preferred_size);
    printf("\n");
  } else {
    //strncpy((char *)buffer, manifest + *offset, *offset - strlen(manifest));  
    printf("LAST COPY: %d bytes\n", cose.ciphertext_len - *offset);
    memcpy((char *)buffer, (char *)cose.ciphertext + *offset, cose.ciphertext_len - *offset);
    printf("SENDING: ");
    PRINTF_HEX(buffer, cose.ciphertext_len - *offset);
    printf("\n");
    printf("LAST LENGTH: %d LAST BUFFER: %s\n", cose.ciphertext_len - *offset, buffer);
    end = 1;
  }
  
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
  // End block transmission if exceeding some limit or EOF found in manifest file
  if(*offset >= CHUNKS_TOTAL || end == 1){// || feof(fd)) {
    // End of block transfer
    printf("END\n");
    *offset = -1;
    end = 0;
    transmit = 0;
  }

}
