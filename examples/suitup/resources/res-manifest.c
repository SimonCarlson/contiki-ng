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
static char *manifest= "{\"0\": 1, \"1\": \"1553762654\", \"2\": [{\"0\": 0, \"1\": \"4be0643f-1d98-573b-97cd-ca98a65347dd\"}, {\"0\": 1, \"1\": \"18ce9adf-9d2e-57a3-9374-076282f3d95b\"}], \"3\": [], \"4\": 0, \"5\": {\"0\": 1, \"1\": 184380, \"2\": 0, \"3\": [{\"0\": \"update/image\", \"1\": \"ac526296b4f53eed4ab337f158afc12755bd046d0982b4fa227ee09897bc32ef\"}]}, \"6\": [{}], \"7\": [{}], \"8\": [{}]}";

static void
res_manifest_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  static int transmit = 0;
  static opt_cose_encrypt_t cose;
  char data[341];
  PRINTF("MANIFEST RESOURCE\n");
  int32_t strpos = 0;
  printf("OFFSET: %d\n", *offset);
  if(*offset >= CHUNKS_TOTAL) {
    coap_set_status_code(response, BAD_OPTION_4_02);
    const char *error_msg = "BlockOutOfScope";
    coap_set_payload(response, error_msg, strlen(error_msg));
    return;
  }

  if(!transmit) {
	  uint8_t cose_buffer = 0;
	  char *aad = "0011bbcc22dd44ee55ff660077";
	  uint8_t nonce[7] = {0, 1, 2, 3, 4, 5, 6};	// Hard coded nonce for example
	  uint8_t key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	  uint8_t ciphertext_buffer[strlen(manifest) +8]; // +8 för tag-len

	  OPT_COSE_Init(&cose);
	  OPT_COSE_SetAlg(&cose, COSE_Algorithm_AES_CCM_64_64_128);
	  OPT_COSE_SetNonce(&cose, nonce, 7);
	  OPT_COSE_SetContent(&cose, (uint8_t *)manifest, strlen(manifest));
	  OPT_COSE_SetCiphertextBuffer(&cose, ciphertext_buffer, strlen(manifest) + 8);
	  OPT_COSE_SetAAD(&cose, (uint8_t *)aad, strlen(aad));
	  OPT_COSE_Encrypt(&cose, key, 16);
	  OPT_COSE_Encode(&cose, &cose_buffer);
    
    transmit = 1;
  }

  printf("Before strncpy\n");
  //strncpy(data, (char *)cose.ciphertext, 2);
  memcpy(data, (char *)cose.ciphertext + *offset, preferred_size);
  printf("DATA: %s\n", data);
  printf("DATA LEN: %d\n", strlen(data));

  // Generate data; copy manifest chunk by chunk into buffer, update strpos with bytes
  // copied
  //FILE *fd = fopen("/home/rzmd/Documents/git-repos/contiki-ng/examples/suitup/example-manifest.json", "r");
  //int bytes;
  //fseek(fd, *offset, SEEK_CUR);
  //bytes = fread((char*)buffer, 1, preferred_size, fd);
  
  // TODO: Send data from ciphertext instead of manifest buffer
  static int end = 0;
  if(*offset > cose.ciphertext_len) {
    //strncpy((char *)buffer, manifest + *offset, *offset - strlen(manifest));  
    memcpy((char *)buffer, (char *)cose.ciphertext + *offset, *offset - cose.ciphertext_len);
    end = 1;
  } else {
    //strncpy((char *)buffer, manifest + *offset, preferred_size);
    printf("Copying\n");
    memcpy((char *)buffer, (char *)cose.ciphertext + *offset, preferred_size);
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