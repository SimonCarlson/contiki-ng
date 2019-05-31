/**
 * \file
 *      Software updates data generation resource
 * \author
 *      Simon Carlson <scarlso@kth.se>
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
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

static void res_image_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);
void oscoap_printf_hex(unsigned char*, unsigned int);

RESOURCE(res_image,
         "title=\"Update image",
         res_image_handler,
         NULL,
         NULL,
         NULL);

#define BLOCKS_TOTAL 10 // Each block is 32 bytes total, of which 24 is data, with one byte for null-termination

static void res_image_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  PRINTF("IMAGE RESOURCE\n");
  int length = 24;
  static int block = 1;
  static int end = 0;

  uint8_t data[32];
  opt_cose_encrypt_t cose;
  uint8_t cose_buffer = 0;
  char *aad = "0011bbcc22dd44ee55ff660077"; // Chosen from RFC 8152
  uint8_t nonce[7] = {0, 1, 2, 3, 4, 5, 6};
  uint8_t key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  uint8_t ciphertext_buffer[length + 8]; // 8 longer than plaintext for tag

  PRINTF("BLOCK: %d\n", block);
  // Format some data into a buffer
  // Casting it to avoid type error when compiling native vs on Firefly
  int format = (int) *offset;
  snprintf((char*)data, 24, "|%d||%d||%d||%d||%d||%d||%d||%d|", format, format, format, format, format, format, format, format);
  PRINTF("Data plaintext: ");
  for(int i = 0; i < length; i++) {
    PRINTF("%c", data[i]);
  }
  PRINTF("\n");

  // Encrypt it
  OPT_COSE_Init(&cose);
  OPT_COSE_SetAlg(&cose, COSE_Algorithm_AES_CCM_64_64_128);
  OPT_COSE_SetNonce(&cose, nonce, 7);
  OPT_COSE_SetContent(&cose, (uint8_t *)data, length);
  OPT_COSE_SetCiphertextBuffer(&cose, ciphertext_buffer, length + 8);
  OPT_COSE_SetAAD(&cose, (uint8_t *)aad, strlen(aad));
  OPT_COSE_Encrypt(&cose, key, 16);
  OPT_COSE_Encode(&cose, &cose_buffer);
  PRINTF("Ciphertext: ");
  PRINTF_HEX(cose.ciphertext, cose.ciphertext_len);
  PRINTF("\n ciphertext len: %d\n", cose.ciphertext_len);

  memcpy((char *)buffer, (char *)cose.ciphertext, 32);
  if(block >= BLOCKS_TOTAL) {
    // Ends block transfer
    PRINTF("Setting end to 1\n");
    end = 1;
  }

  PRINTF("BUFFER: ");
  for(int i = 0; i < 32; i++) {
    PRINTF("%02x ", buffer[i]);
  }
  PRINTF("\n");
  
  block++;

  // Output from COSE encrypt is always 32 bytes long
  coap_set_payload(response, buffer, 32);
  // Update offset for next pass
  *offset += 32;
  // End of block transfer
  if(end){
    PRINTF("END\n");
    *offset = -1;
    end = 0;
    block = 1;
  }
}
