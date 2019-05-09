#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "cfs/cfs.h"
#include "coap-engine.h"
#include "opt-cose.h"

#define DEBUG 0
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINTF_HEX(data, len) 	oscoap_printf_hex(data, len)
#else
#define PRINTF(...)
#define PRINTF_HEX(data, len)
#endif

void oscoap_printf_hex(unsigned char*, unsigned int);
static void res_manifest_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_manifest,
         "title=\"Update manifest",
         res_manifest_handler,
         NULL,
         NULL,
         NULL);
  
//static char *manifest= "{\"0\": 1, \"1\": 1555415686, \"2\": [{\"0\": 0, \"1\": \"4be0643f-1d98-573b-97cd-ca98a65347dd\"}, {\"0\": 1, \"1\": \"18ce9adf-9d2e-57a3-9374-076282f3d95b\"}], \"3\": [], \"4\": 0, \"5\": {\"0\": 3, \"1\": 704, \"2\": 0, \"3\": [{\"0\": \"update/image\", \"1\": \"8c2859fca075e24d1a79d0b6cdfdfe5c07da8c203a892700538efd96f789b355\"}]}, \"6\": [], \"7\": [], \"8\": []}";
static char *manifest = "{\"0\": 1, \"1\": 1556783337, \"2\": [{\"0\": 0, \"1\": \"4be0643f-1d98-573b-97cd-ca98a65347dd\"}, {\"0\": 1, \"1\": \"18ce9adf-9d2e-57a3-9374-076282f3d95b\"}], \"3\": [], \"4\": 0, \"5\": {\"0\": 3, \"1\": 11500, \"2\": 0, \"3\": [{\"0\": \"update/image\", \"1\": \"37ce827871e6c63e9e5aab92f84c579f7aa5c6be0c3980cb6e30a102396abfd6\"}]}, \"6\": [], \"7\": [], \"8\": []}";

static void
res_manifest_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  static int transmit = 0;
  static int end = 0;

  static opt_cose_encrypt_t cose;
  // Cannot make it smaller without running into stack smashing. I think having a static
  // COSE object and/or ciphertext buffer causes issues with the stack. Should be 16 long
  uint8_t data[100] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  uint8_t cose_buffer = 0;
  char *aad = "0011bbcc22dd44ee55ff660077"; // Chosen from RFC 8152
  uint8_t nonce[7] = {0, 1, 2, 3, 4, 5, 6};
  static uint8_t ciphertext_buffer[332]; // +8 for tag-len
  PRINTF("MANIFEST RESOURCE\n");

  if(!transmit) {
    // Here the server would pick a manifest to encrypt and send depending on the
    // information in the profile
    char profile_data[37 + 37 + 4 + 2];
    int fd = cfs_open("profile", CFS_READ);
    cfs_read(fd, profile_data, sizeof(profile_data));
    printf("Manifest request from device with profile:\n%s\n", profile_data);
    cfs_close(fd);

    // If transmission is starting, encrypt entire manifest
    PRINTF("Manifest: %s\n", manifest);
	  OPT_COSE_Init(&cose);
	  OPT_COSE_SetAlg(&cose, COSE_Algorithm_AES_CCM_64_64_128);
	  OPT_COSE_SetNonce(&cose, nonce, 7);
	  OPT_COSE_SetContent(&cose, (uint8_t *)manifest, 324);
	  OPT_COSE_SetCiphertextBuffer(&cose, ciphertext_buffer, 332);
	  OPT_COSE_SetAAD(&cose, (uint8_t *)aad, strlen(aad));
	  OPT_COSE_Encrypt(&cose, data, 16);
	  OPT_COSE_Encode(&cose, &cose_buffer);

    PRINTF("Ciphertext manifest: \n");
    PRINTF_HEX(ciphertext_buffer, 332);
    PRINTF("\n");
    transmit = 1;
  }

  if(cose.ciphertext_len - *offset > 32) {
    // Send a block of size 32
    memcpy((char *)buffer, (char *)cose.ciphertext + *offset, preferred_size);
    PRINTF("SENDING: ");
    PRINTF_HEX(buffer, preferred_size);
    PRINTF("\n");
  } else {
    // Send the remaining data
    memcpy((char *)buffer, (char *)cose.ciphertext + *offset, cose.ciphertext_len - *offset);
    PRINTF("SENDING: ");
    PRINTF_HEX(buffer, cose.ciphertext_len - *offset);
    PRINTF("\n");
    end = 1;
  }

  coap_set_payload(response, buffer, preferred_size);
  // Update offset for next pass
  *offset += preferred_size;
  // End of block transfer
  if(end == 1){
    *offset = -1;
    end = 0;
    transmit = 0;
  }

}
