/**
 * \file
 *      Software updates example server
 * \author
 *      Simon Carlson <scarlso@kth.se>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "coap-engine.h"
#include "coap-keystore-simple.h"
#include "rpl.h"
#include "rpl-dag-root.h"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

/*
 * Resources to be activated need to be imported through the extern keyword.
 * The build system automatically compiles the resources in the corresponding sub-directory.
 */
extern coap_resource_t res_register, res_manifest, res_image;

PROCESS(er_example_server, "Erbium Example Server");
AUTOSTART_PROCESSES(&er_example_server);

PROCESS_THREAD(er_example_server, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();

  PRINTF("Starting Erbium Example Server\n");
  PRINTF("uIP buffer: %u\n", UIP_BUFSIZE);
  PRINTF("LL header: %u\n", UIP_LLH_LEN);
  PRINTF("IP+UDP header: %u\n", UIP_IPUDPH_LEN);
  PRINTF("CoAP max chunk: %u\n", COAP_MAX_CHUNK_SIZE);

  rpl_dag_root_start();
  //rpl_dag_root_init_dag_immediately();  // Might have to be called instead of rpl_dag_root_start() depending on contiki-ng version
  /* Initialize the REST engine. */
  coap_engine_init();
  coap_keystore_simple_init();

  /*
   * Bind the resources to their Uri-Path.
   * WARNING: Activating twice only means alternate path, not two instances!
   * All static variables are the same for each URI path.
   */
  coap_activate_resource(&res_register, "update/register");
  coap_activate_resource(&res_manifest, "update/manifest");
  coap_activate_resource(&res_image, "update/image");

  /* Define application-specific events here. */
  while(1) {
    PROCESS_WAIT_EVENT();
  }                             /* while (1) */

  PROCESS_END();
}
