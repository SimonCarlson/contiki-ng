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
//#include "coap-callback-api.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "client"
#define LOG_LEVEL  LOG_LEVEL_COAP

/* FIXME: This server address is hard-coded for Cooja and link-local for unconnected border router. */
#define SERVER_EP "coap://[fe80::201:1:1:1]"
#define VENDOR_ID "74738ff5536759589aee98fffdcd1876"
#define CLASS_ID "28718ff5930282177ccc14aefbcd1276"
#define VERSION "1.0"
#define INTERVAL 4
#define TIMEOUT 1

static char query_data[128]; /* allocate some data for queries and updates */
//static coap_request_state_t rd_request_state;
static char image_url[128];

PROCESS(update_client, "Update client");
AUTOSTART_PROCESSES(&update_client);


/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void
client_chunk_handler(coap_message_t *response)
{
  printf("REGISTER CALLBACK\n");
  const uint8_t *chunk;

  int len = coap_get_payload(response, &chunk);

  printf("Response: %.*s", len, (char *)chunk);
}


void
manifest_parser(coap_message_t *response)
{
  printf("MANIFEST CALLBACK\n");
  const uint8_t *chunk;

  int len = coap_get_payload(response, &chunk);
  strncpy(image_url, "update/image", strlen("update/image"));

  printf("Response: %.*s", len, (char *)chunk);
}


void
update_handler(coap_message_t *response)
{
  printf("UPDATE CALLBACK\n");
  const uint8_t *chunk;

  int len = coap_get_payload(response, &chunk);

  printf("Response: %.*s", len, (char *)chunk);
}


PROCESS_THREAD(update_client, ev, data)
{
  static struct etimer et;
  coap_endpoint_t server_ep;
  PROCESS_BEGIN();
  static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */

  //coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
  //coap_endpoint_print(&server_ep);
  /* receives all CoAP messages */
  coap_engine_init();
  coap_keystore_simple_init();

  etimer_set(&et, CLOCK_SECOND * INTERVAL);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

    printf("Send packet to update/register\n");
    coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
    int res = coap_endpoint_is_connected(&server_ep);
    printf("CONNECT RESULT: %d\n", res);
    coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
    coap_set_header_uri_path(request, "update/register");

    // const char msg[] = "Toggle!";
    // coap_set_payload(request, (uint8_t *)msg, sizeof(msg) - 1);

    // Copy POST data into buffer
    snprintf(query_data, sizeof(query_data) - 1, "?vid=%s&cid=%s&v=%s", "VENDOR_ID", "CLASS_ID", "VERSION");
    int bytes = coap_set_header_uri_query(request, query_data); 
    printf("URI QUERY: %s, LENGTH: %d\n", request->uri_query, bytes);
    LOG_INFO_COAP_EP(&server_ep);
    LOG_INFO_("\n");

    COAP_BLOCKING_REQUEST(&server_ep, request, client_chunk_handler);
    printf("Registration done\n");

    coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
    coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
    coap_set_header_uri_path(request, "update/manifest");
    COAP_BLOCKING_REQUEST(&server_ep, request, manifest_parser);
    printf("Manifest done\n");

    coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
    coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
    coap_set_header_uri_path(request, image_url);
    COAP_BLOCKING_REQUEST(&server_ep, request, update_handler);
    printf("Image done\n");

    printf("\n--Done--\n");

  PROCESS_END();
}
