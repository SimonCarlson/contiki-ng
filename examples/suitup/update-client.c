/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *      Erbium (Er) CoAP client example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "coap-keystore-simple.h"
#include "rpl.h"
#include "parse-test.h"
//#include "coap-callback-api.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "client"
#define LOG_LEVEL  LOG_LEVEL_COAP

/* FIXME: This server address is hard-coded for Cooja and link-local for unconnected border router. */
#define SERVER_EP "coaps://[fe80::201:1:1:1]"
//#define SERVER_EP "coap://[fd00::302:304:506:708]"
#define VENDOR_ID "4be0643f-1d98-573b-97cd-ca98a65347dd"
#define CLASS_ID "18ce9adf-9d2e-57a3-9374-076282f3d95b"
#define VERSION "1.0"
#define INTERVAL 1
#define TIMEOUT 1

// TODO: Optimize, size of IDs known
//static char query_data[128]; /* allocate some data for queries and updates */
//static coap_request_state_t rd_request_state;
// TODO: Assumption, fix dynamically?
//static char manifest_buffer[451];
char *manifest_buffer = "{\"0\": 1, \"1\": 1554114615, \"2\": [{\"0\": 0, \"1\": \"4be0643f-1d98-573b-97cd-ca98a65347dd\"}, {\"0\": 1, \"1\": \"18ce9adf-9d2e-57a3-9374-076282f3d95b\"}], \"3\": [], \"4\": 0, \"5\": {\"0\": 1, \"1\": 184380, \"2\": 0, \"3\": [{\"0\": \"update/image\", \"1\": \"ac526296b4f53eed4ab337f158afc12755bd046d0982b4fa227ee09897bc32ef\"}]}, \"6\": [], \"7\": [], \"8\": []}";
static int manifest_offset = 0;
char digest[256];

PROCESS(update_client, "Update client");
AUTOSTART_PROCESSES(&update_client);


void
register_callback(coap_message_t *response)
{
  printf("REGISTER CALLBACK\n");
  const uint8_t *chunk;

  int len = coap_get_payload(response, &chunk);

  printf("Response: %.*s\n", len, (char *)chunk);
}


void
manifest_callback(coap_message_t *response)
{
  printf("MANIFEST CALLBACK\n");
  const uint8_t *chunk;

  coap_get_payload(response, &chunk);
  int copied_bytes = strlen((char *)chunk);
  strncpy(manifest_buffer + manifest_offset, (char *)chunk, copied_bytes);
  manifest_offset += copied_bytes;
  printf("Response: %s length: %ld\n", (char *)chunk, strlen((char *)chunk));
}


void
image_callback(coap_message_t *response)
{
  printf("IMAGE CALLBACK\n");
  const uint8_t *chunk;

  int len = coap_get_payload(response, &chunk);

  printf("Response: %.*s\n", len, (char *)chunk);
}


int manifest_checker(manifest_t *manifest) {
  printf("VENDOR ID: %d\n", strcmp(manifest->preConditions->value, VENDOR_ID));
  printf("CLASS ID: %d\n", strcmp(manifest->preConditions->next->value, CLASS_ID));
  strcpy(digest, manifest->payloadInfo->URLDigest->digest);
  return 1;
}


PROCESS_THREAD(update_client, ev, data)
{
  static struct etimer et;
  static coap_endpoint_t server_ep;
  PROCESS_BEGIN();
  static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */

  //coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
  //coap_endpoint_print(&server_ep);
  /* receives all CoAP messages */
  coap_engine_init();
  coap_keystore_simple_init();

  etimer_set(&et, CLOCK_SECOND * INTERVAL);
  //PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

    /*printf("Send packet to update/register\n");
    coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
    printf("CLIENT CONNECTED? : %d\n", coap_endpoint_is_connected(&server_ep));
    coap_endpoint_connect(&server_ep);
    coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
    coap_set_header_uri_path(request, "update/register");

    // const char msg[] = "Toggle!";
    //snprintf(query_data, sizeof(query_data) - 1, "%s&%s&%s", VENDOR_ID, CLASS_ID, VERSION);
    //coap_set_payload(request, (uint8_t *)query_data, sizeof(query_data) - 1);

    // Copy POST data into buffer
    snprintf(query_data, sizeof(query_data) - 1, "?vid=%s&cid=%s&v=%s", VENDOR_ID, CLASS_ID, VERSION);
    int bytes = coap_set_header_uri_query(request, query_data); 
    printf("URI QUERY: %s, LENGTH: %d\n", request->uri_query, bytes);
    LOG_INFO_COAP_EP(&server_ep);
    LOG_INFO_("\n");

    COAP_BLOCKING_REQUEST(&server_ep, request, register_callback);
    printf("Registration done\n");

    coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
    coap_set_header_uri_path(request, "update/manifest");
    COAP_BLOCKING_REQUEST(&server_ep, request, manifest_callback);*/
    manifest_t m;
    condition_t pre;
    pre.type = 1;
    pre.value = "0";
    pre.next = NULL;
    m.preConditions = &pre;
    printf("%d\n", m.preConditions->type);

    manifest_t manifest;
    condition_t preConditions;
    condition_t nextPreCondition;
    condition_t postConditions;
    payloadInfo_t payloadInfo;
    URLDigest_t URLDigest;
    URLDigest_t precursorImage;
    URLDigest_t dependencies;
    option_t options;

    preConditions.next = &nextPreCondition;
    manifest.preConditions = &preConditions;
    manifest.postConditions = &postConditions;
    payloadInfo.URLDigest = &URLDigest;
    manifest.payloadInfo = &payloadInfo;
    manifest.precursorImage = &precursorImage;
    manifest.dependencies = &dependencies;
    manifest.options = &options;
    printf("Starting parser\n");
    manifest_parser(&manifest, manifest_buffer);
    print_manifest(&manifest);
    int accept = manifest_checker(&manifest);
    accept = 0;
    printf("Manifest done\n");

    if(accept) {
      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
      coap_set_header_uri_path(request, manifest.payloadInfo->URLDigest->URL);
      COAP_BLOCKING_REQUEST(&server_ep, request, image_callback);
      printf("Image done\n");
      printf("MANIFEST: %s\n", manifest_buffer);
      printf("MANIFEST LENGTH: %ld\n", strlen(manifest_buffer));
      printf("\n--Done--\n");
    } else {
      printf("Mismatched manifest.\n");
    }

  PROCESS_END();
}