#include <stdlib.h>
#include <string.h>
#include "coap-engine.h"

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

  static int transmit = 0;
  static int file_len;
  FILE *fd = fopen("/home/user/contiki-ng/examples/suitup/client-cert.pem", "rb");

  if(!transmit) {
    fseek(fd, 0L, SEEK_END);
    file_len = ftell(fd);
    printf("FILE_LEN: %d\n", file_len);
    rewind(fd);
    transmit = 1;
  }
  
  static int end = 0;
  int bytes;
  fseek(fd, *offset, SEEK_CUR);
  if(*offset > file_len - preferred_size) {
    //strncpy((char *)buffer, image + *offset, *offset - strlen(image));
    printf("LAST OFFSET: %d\n", *offset);
    bytes = fread(buffer, 1, *offset - file_len, fd);
    end = 1;
  } else {
    //strncpy((char *)buffer, image + *offset, preferred_size);
    bytes = fread(buffer, 1, preferred_size, fd);
  }
  
  printf("BUFFER: %s\n", buffer);
  printf("BYTES: %d\n", bytes);
  strpos += bytes;
  
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
