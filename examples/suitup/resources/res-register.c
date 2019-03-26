#include <stdlib.h>
#include <string.h>
#include "coap-engine.h"

#include "coap-log.h"
#define LOG_MODULE "client"
#define LOG_LEVEL  LOG_LEVEL_COAP

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

static void res_register_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

/*
 * A handler function named [resource name]_handler must be implemented for each RESOURCE.
 * A buffer for the response payload is provided through the buffer pointer. Simple resources can ignore
 * preferred_size and offset, but must respect the REST_MAX_CHUNK_SIZE limit for the buffer.
 * If a smaller block size is requested for CoAP, the REST framework automatically splits the data.
 */
RESOURCE(res_register,
         "title=\"Update registration",
         res_register_handler,
         res_register_handler,  // POST handler
         NULL,
         NULL);

static void
res_register_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  PRINTF("REGISTER RESOURCE\n");
  const char *vendor_id;
  //const char *class_id = NULL;
  //const char *version = NULL;
  /* Some data that has the length up to REST_MAX_CHUNK_SIZE. For more, see the chunk resource. */
  char const *const message = "Hello World! ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy";
  int length = 12; /*           |<-------->| */

  if(coap_get_query_variable(request, "vid", &vendor_id)) {
    printf("Vendor id: %s\n", vendor_id);
    //memcpy(buffer, vendor_id, length);
  }

  printf("Vendor id: %s\n", vendor_id);

  coap_set_status_code(response, CREATED_2_01);
  memcpy(buffer, message, length);
  coap_set_header_content_format(response, TEXT_PLAIN); /* text/plain is the default, hence this option could be omitted. */
  coap_set_header_etag(response, (uint8_t *)&length, 1);
  coap_set_payload(response, buffer, length);
}
