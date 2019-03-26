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

static void res_manifest_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

/*
 * A handler function named [resource name]_handler must be implemented for each RESOURCE.
 * A buffer for the response payload is provided through the buffer pointer. Simple resources can ignore
 * preferred_size and offset, but must respect the REST_MAX_CHUNK_SIZE limit for the buffer.
 * If a smaller block size is requested for CoAP, the REST framework automatically splits the data.
 */
RESOURCE(res_manifest,
         "title=\"Update manifest",
         res_manifest_handler,
         NULL,
         NULL,
         NULL);

#define CHUNKS_TOTAL 2050 // How to determine? Size of file? 
char *manifest= "{\"versionID\": 1,\"sequenceNumber\": 1,\"preConditions\": [{\"type\": 0,\"UUID\": \"74738ff5-5367-5958-9aee-98fffdcd1876\"},{\"type\": 1,\"UUID\": \"28718ff5-9302-8217-7ccc-14aefbcd1276\"}],\"postConditions\": [],\"contentKeyMethod\": 0,\"payloadInfo\": {\"format\": 0,\"size\": 512,\"storage\": 0,\"URLdigest\": [{\"URL\": \"coaps://fake-url\",\"digest\": \"6b6bf0bce018a46a263151f7f662c2f94125f39ba68b48160ee222853201a863\"}]},\"precursorImage\": [{}],\"dependencies\": [{}],\"options\": [{}]}";

static void
res_manifest_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  PRINTF("MANIFEST RESOURCE\n");
  int32_t strpos = 0;
  printf("OFFSET: %d\n", *offset);
  if(*offset >= CHUNKS_TOTAL) {
    coap_set_status_code(response, BAD_OPTION_4_02);
    const char *error_msg = "BlockOutOfScope";
    coap_set_payload(response, error_msg, strlen(error_msg));
    return;
  }

  

  // Generate data; copy manifest chunk by chunk into buffer, update strpos with bytes
  // copied
  //FILE *fd = fopen("/home/rzmd/Documents/git-repos/contiki-ng/examples/suitup/example-manifest.json", "r");
  //int bytes;
  //fseek(fd, *offset, SEEK_CUR);
  //bytes = fread((char*)buffer, 1, preferred_size, fd);
  
  static int end = 0;
  if(strlen(manifest) < *offset) {
    strncpy((char*)buffer, manifest + *offset, *offset - strlen(manifest));  
    end = 1;
  } else {
    strncpy((char*)buffer, manifest + *offset, preferred_size);
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
  }

}
