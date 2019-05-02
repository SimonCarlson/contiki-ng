#include <stdlib.h>
#include <string.h>
#include "cfs/cfs.h"
#include "coap-engine.h"
#include "sys/energest.h"

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
  uint64_t cpu_start, cpu_time, lpm_start, lpm_time, dlpm_start, dlpm_time, tx_start, tx_time, rx_start, rx_time;
  energest_flush();
  cpu_start = energest_type_time(ENERGEST_TYPE_CPU);
  lpm_start = energest_type_time(ENERGEST_TYPE_LPM);
  dlpm_start = energest_type_time(ENERGEST_TYPE_DEEP_LPM);
  tx_start = energest_type_time(ENERGEST_TYPE_TRANSMIT);
  rx_start = energest_type_time(ENERGEST_TYPE_LISTEN);
  char vendor_id[37];
  char class_id[37];
  char version[4];
  const char *chunk;

  coap_get_query_variable(request, "vid", &chunk);
  PRINTF("CHUNK: %s\n", chunk);
  char *p1, *p2;
  // Find end of first argument
  p2 = strstr((char *)chunk, "&");
  memcpy(vendor_id, chunk, p2 - chunk);
  vendor_id[36] = '\0';
  PRINTF("Vendor id: %s\n", vendor_id);

  // Find start and end of second argument
  p1 = strstr(chunk, "=");
  p2 = strstr(p1, "&");
  memcpy(class_id, p1 + 1, p2 - p1 - 1);
  class_id[36] = '\0';
  PRINTF("Class id: %s\n", class_id);

  // Advance past the delimiter
  p1++;
  p1 = strstr(p1, "=");
  p2 = strstr(p1, "&");
  // Version is 3 long
  memcpy(version, p1 + 1, 3);
  version[3] = '\0';
  PRINTF("Version: %s\n", version);

  char profile_data[37 + 37 + 4 + 2];
  snprintf(profile_data, sizeof(profile_data), "%s\n%s\n%s\n", vendor_id, class_id, version);
  int fd = cfs_open("profile", CFS_WRITE);
  cfs_write(fd, profile_data, sizeof(profile_data));
  cfs_close(fd);


  coap_set_status_code(response, CREATED_2_01);
  coap_set_header_content_format(response, TEXT_PLAIN); /* text/plain is the default, hence this option could be omitted. */
  energest_flush();
  cpu_time = energest_type_time(ENERGEST_TYPE_CPU) - cpu_start;
  lpm_time = energest_type_time(ENERGEST_TYPE_LPM) - lpm_start;
  dlpm_time = energest_type_time(ENERGEST_TYPE_DEEP_LPM) - dlpm_start;
  tx_time = energest_type_time(ENERGEST_TYPE_TRANSMIT) - tx_start;
  rx_time = energest_type_time(ENERGEST_TYPE_LISTEN) - rx_start;
  printf("Register: CPU: %llus LPM: %llus DLPM: %llus TX: %llus RX: %llus\n", cpu_time, lpm_time, dlpm_time, tx_time, rx_time);
}
