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
//#include "dev/sha256.h"
#include "manifest-parser.h"
#include "opt-cose.h"
//#include "coap-callback-api.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "client"
#define LOG_LEVEL  LOG_LEVEL_COAP

/* FIXME: This server address is hard-coded for Cooja and link-local for unconnected border router. */
#define SERVER_EP "coap://[fe80::201:1:1:1]"
//#define SERVER_EP "coap://[fd00::302:304:506:708]"
#define VENDOR_ID "4be0643f-1d98-573b-97cd-ca98a65347dd"
#define CLASS_ID "18ce9adf-9d2e-57a3-9374-076282f3d95b"
#define VERSION "1.0"
#define INTERVAL 1
#define TIMEOUT 1

// TODO: Assumption, fix dynamically?
static char manifest_buffer[512];
static char image_buffer[1024];
//char *manifest_buffer = "{\"0\": 1, \"1\": 1554114615, \"2\": [{\"0\": 0, \"1\": \"4be0643f-1d98-573b-97cd-ca98a65347dd\"}, {\"0\": 1, \"1\": \"18ce9adf-9d2e-57a3-9374-076282f3d95b\"}], \"3\": [], \"4\": 0, \"5\": {\"0\": 1, \"1\": 184380, \"2\": 0, \"3\": [{\"0\": \"update/image\", \"1\": \"ac526296b4f53eed4ab337f158afc12755bd046d0982b4fa227ee09897bc32ef\"}]}, \"6\": [], \"7\": [], \"8\": []}";
static int manifest_offset = 0;
static int image_offset = 0;

#define PRINTF_HEX(data, len) 	oscoap_printf_hex(data, len)
void oscoap_printf_hex(unsigned char*, unsigned int);

struct value_t {
    char value[256];        // Digest is SHA-256, needs to fit
};

// TODO: Why does it not work with blocks = 1 and freeing the memory?
#define BLOCKS 6
MEMB(manifestValue, struct value_t, BLOCKS);

PROCESS(update_client, "Update client");
AUTOSTART_PROCESSES(&update_client);


void register_callback(coap_message_t *response) {
    printf("REGISTER CALLBACK\n");
    const uint8_t *chunk;

    int len = coap_get_payload(response, &chunk);

    printf("Response: %.*s\n", len, (char *)chunk);
}


void manifest_callback(coap_message_t *response) {
    printf("MANIFEST CALLBACK\n");
    const uint8_t *chunk;

    coap_get_payload(response, &chunk);
    //int copied_bytes = strlen((char *)chunk);
    memcpy(manifest_buffer + manifest_offset, (char *)chunk, 32);
    manifest_offset += 32;
}


void image_callback(coap_message_t *response) {
    printf("IMAGE CALLBACK\n");
    const uint8_t *chunk;

    coap_get_payload(response, &chunk);
    //int copied_bytes = strlen((char *)chunk);
    printf("RECEIVED: %s\n", chunk);
    memcpy(image_buffer + image_offset, (char *)chunk, 32);
    image_offset += 32;
}


int manifest_checker(manifest_t *manifest) {
    // Check pre conditions etc
    if(strcmp(manifest->preConditions->value, VENDOR_ID) != 0) {
        printf("Mismatched vendor ID.\n");
        return 0;
    }

    if(strcmp(manifest->preConditions->next->value, CLASS_ID) != 0) {
        printf("Mismatched class ID.\n");
        return 0;
    }

    return 1;
}


PROCESS_THREAD(update_client, ev, data) {
    PROCESS_BEGIN();
    static struct etimer et;
    static coap_endpoint_t server_ep;
    static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */
    // TODO: Optimize, size of IDs known
    char query_data[90];

    coap_engine_init();
    coap_keystore_simple_init();

    coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
    LOG_INFO_COAP_EP(&server_ep);
    LOG_INFO_("\n");

    // Connect to server endpoint
    coap_endpoint_connect(&server_ep);
    etimer_set(&et, CLOCK_SECOND * INTERVAL);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    printf("CLIENT CONNECTED? : %d\n", coap_endpoint_is_connected(&server_ep));
    
    // Register to server
    coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
    coap_set_header_uri_path(request, "update/register");
    // Copy POST data into buffer
    snprintf(query_data, sizeof(query_data) - 1, "?vid=%s&cid=%s&v=%s", VENDOR_ID, CLASS_ID, VERSION);
    int bytes = coap_set_header_uri_query(request, query_data); 
    printf("URI QUERY: %s, LENGTH: %d\n", request->uri_query, bytes);
    COAP_BLOCKING_REQUEST(&server_ep, request, register_callback);
    printf("Registration done\n");

    // Get manifest from server
    coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
    coap_set_header_uri_path(request, "update/manifest");
    COAP_BLOCKING_REQUEST(&server_ep, request, manifest_callback);

    // Decode and decrypt manifest into plaintext
    opt_cose_encrypt_t decrypt;
	char *aad2 = "0011bbcc22dd44ee55ff660077";
	uint8_t decrypt_buffer[327];
	uint8_t key2[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	uint8_t buffer2 = 0;
    uint8_t nonce[7] = {0, 1, 2, 3, 4, 5, 6};	

	OPT_COSE_Init(&decrypt);
	OPT_COSE_SetAlg(&decrypt, COSE_Algorithm_AES_CCM_64_64_128);
	OPT_COSE_SetNonce(&decrypt, nonce, 7);
	OPT_COSE_SetAAD(&decrypt, (uint8_t*)aad2, strlen(aad2));
	OPT_COSE_SetContent(&decrypt, decrypt_buffer, 327);
	OPT_COSE_SetCiphertextBuffer(&decrypt, (uint8_t*)manifest_buffer, 335);
	OPT_COSE_Decode(&decrypt, &buffer2, 1);
	OPT_COSE_Decrypt(&decrypt, key2, 16);
    printf("PLAINTEXT: %s\n", decrypt.plaintext);
    printf("PLAINTEXT LENGTH: %d\n", strlen((char *)decrypt.plaintext));

    // Declare and structure manifest for parsing
    manifest_t manifest;
    condition_t preConditions, nextPreCondition, postConditions;
    payloadInfo_t payloadInfo;
    URLDigest_t URLDigest, precursorImage, dependencies;
    option_t options;

    preConditions.next = &nextPreCondition;
    manifest.preConditions = &preConditions;
    manifest.postConditions = &postConditions;
    payloadInfo.URLDigest = &URLDigest;
    manifest.payloadInfo = &payloadInfo;
    manifest.precursorImage = &precursorImage;
    manifest.dependencies = &dependencies;
    manifest.options = &options;
    
    // Parse and check manifest
    manifest_parser(&manifest, (char *)decrypt.plaintext);
    print_manifest(&manifest);
    int accept = manifest_checker(&manifest);
    printf("Accept: %d\n", accept);
    
    if(accept) {
        printf("Manifest accepted.\n");
        // Get image from server
        coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
        //coap_set_header_uri_path(request, manifest.payloadInfo->URLDigest->URL);
        coap_set_header_uri_path(request, "update/image");
        COAP_BLOCKING_REQUEST(&server_ep, request, image_callback);
        // TODO: Decode and decrypt image
        
        opt_cose_encrypt_t decrypt;
	    char *aad2 = "0011bbcc22dd44ee55ff660077";
	    uint8_t key2[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	    uint8_t buffer2 = 0;
        uint8_t nonce[7] = {0, 1, 2, 3, 4, 5, 6};	
        uint8_t decrypt_buffer2[704];
        printf("Image buffer: ");
        PRINTF_HEX((unsigned char *)image_buffer, 712);
        printf("\n");

        OPT_COSE_Init(&decrypt);
	    OPT_COSE_SetAlg(&decrypt, COSE_Algorithm_AES_CCM_64_64_128);
	    OPT_COSE_SetNonce(&decrypt, nonce, 7);
	    OPT_COSE_SetAAD(&decrypt, (uint8_t*)aad2, strlen(aad2));
	    OPT_COSE_SetContent(&decrypt, decrypt_buffer2, 704);
	    OPT_COSE_SetCiphertextBuffer(&decrypt, (uint8_t*)image_buffer, 712);
	    OPT_COSE_Decode(&decrypt, &buffer2, 1);
	    OPT_COSE_Decrypt(&decrypt, key2, 16);
        printf("PLAINTEXT: %s\n", decrypt.plaintext);
        printf("PLAINTEXT LENGTH: %d\n", strlen((char *)decrypt.plaintext));
        // TODO: Check digest of image
    } else {
        printf("Mismatched manifest.\n");
    }

  PROCESS_END();
}

void manifest_parser(manifest_t *manifest_p, char *manifest_string) {
    printf("Parsing at %p: %s\n", manifest_string, manifest_string);
    char *cur_pos = manifest_string;
    int key;
    char *val;
    // Traverse the manifest
    while(*cur_pos != '\0') {
        key = get_next_key(&cur_pos);
        switch(key) {
            case 0:
                // VERSION ID
                val = get_next_value(&cur_pos);
                manifest_p->versionID = atoi(val);
                memb_free(&manifestValue, val);
                //free(val);
                break;
            case 1:
                // SEQUENCE NUMBER
                val = get_next_value(&cur_pos);
                manifest_p->sequenceNumber = atoi(val);
                memb_free(&manifestValue, val);
                //free(val);
                break;
            case 2:
                // PRECONDITIONS
                // First pair (vendor id)
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->preConditions->type = atoi(val);
                memb_free(&manifestValue, val);
                //free(val);
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->preConditions->value = val;
                memb_free(&manifestValue, val);
                ////free(val);

                // Second pair (class id)
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->preConditions->next->type = atoi(val);
                memb_free(&manifestValue, val);
                //free(val);
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->preConditions->next->value = val;
                memb_free(&manifestValue, val);
                ////free(val);

                //preConditions.next = &nextPreCondition;
                //manifest_p->preConditions = &preConditions;
                break;
            case 3:
                // POSTCONDITIONS
                val = get_next_value(&cur_pos);
                //free(val);
                manifest_p->postConditions->type = -1;
                manifest_p->postConditions->value = NULL;
                manifest_p->postConditions->next = NULL;
                memb_free(&manifestValue, val);
                //manifest_p->postConditions = &postConditions;
                break;
            case 4:
                // CONTENT KEY METHOD
                val = get_next_value(&cur_pos);
                manifest_p->contentKeyMethod = atoi(val);
                memb_free(&manifestValue, val);
                //free(val);
                break;
            case 5:
                // PAYLOAD INFO
                // Format
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->payloadInfo->format = atoi(val);
                memb_free(&manifestValue, val);
                //free(val);

                // Size
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->payloadInfo->size = atoi(val);
                memb_free(&manifestValue, val);
                //free(val);

                // Storage
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->payloadInfo->storage = atoi(val);
                memb_free(&manifestValue, val);
                //free(val);

                // Start of URLDigest, skip its key
                get_next_key(&cur_pos);
                // URL
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->payloadInfo->URLDigest->URL = val;
                memb_free(&manifestValue, val);
                ////free(val);

                // digest
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->payloadInfo->URLDigest->digest = val;
                memb_free(&manifestValue, val);
                ////free(val);

                manifest_p->payloadInfo->URLDigest->next = NULL;
                //payloadInfo.URLDigest = &URLDigest;
                //manifest_p->payloadInfo = &payloadInfo;
                break;
            case 6:
                // PRECURSORS
                val = get_next_value(&cur_pos);
                //free(val);
                manifest_p->precursorImage->URL = NULL;
                manifest_p->precursorImage->digest = NULL;
                manifest_p->precursorImage->next = NULL;
                memb_free(&manifestValue, val);
                //manifest_p->precursorImage = &precursorImage;
                break;
            case 7:
                // DEPENDENCIES
                val = get_next_value(&cur_pos);
                //free(val);
                manifest_p->dependencies->URL = NULL;
                manifest_p->dependencies->digest = NULL;
                manifest_p->dependencies->next = NULL;
                memb_free(&manifestValue, val);
                //manifest_p->dependencies = &dependencies;
                break;
            case 8:
                // OPTIONS
                val = get_next_value(&cur_pos);
                //free(val);
                manifest_p->options->type = -1;
                manifest_p->options->value = NULL;
                manifest_p->options->next = NULL;
                memb_free(&manifestValue, val);
                //manifest_p->options = &options;
                break;
        }     
    
    }
}


int get_next_key(char **buffer) {
    char check; // Will hold the candidate for the key value
    while(**buffer != '\0') {
        check = (*buffer)[1];
        // Check for the pattern "X" where X is a digit
        if(**buffer == '"' && is_digit(&check) && *(*buffer + 2) == '"') {
            // Advance the buffer past the current key, to the value (skipping the ':')
            *buffer += 4;
            return atoi(&check);
        } else {
            (*buffer)++;
        }
    }
    return -1;
}

char *get_next_value(char **buffer) {
    char *index = strchr(*buffer, ',');
    int distance;
    // Index == NULL means no comma found, string approaching its end
    // Search instead for closing bracket '}'
    if(index == NULL) {
        index = strchr(*buffer, '}');
    }
    // Distance until end of value (comma separation)
    distance = index - *buffer;

    struct value_t *val = (struct value_t*)memb_alloc(&manifestValue);
    char *ret = val->value;
    // Copy the value field
    strncpy(ret, *buffer, distance);
    // Check if there is a citation mark (meaning value is in string format)
    char *mark = strchr(ret, '"');
    if(mark != NULL) {
        // Move past the first citation mark ...
        ret += mark - ret + 1;
        mark = strchr(ret, '"');
        // ... and cut off the second citation mark
        ret[mark - ret] = '\0';
    } else {
        // Null terminate the string
        ret[distance] = '\0';
    }

    // Advance buffer past the extracted value
    *buffer = *buffer + distance + 1;
    return ret;
}


int is_digit(char *c) {
    while(*c != '\0') {
        if(*c < '0' || *c > '9') {
            return 0;
        }
        c++;
    }
    return 1;
}


void print_manifest(manifest_t *manifest) {
    printf("MANIFEST: %s\n", manifest_buffer);
    printf("MANIFEST LENGTH: %d\n", strlen(manifest_buffer));
    printf("VERSION: %d\n", manifest->versionID);
    printf("SEQUENCE: %d\n", manifest->sequenceNumber);
    printf("PRECOND 1: %d %s\n", manifest->preConditions->type, manifest->preConditions->value);
    printf("PRECOND 2: %d %s\n", manifest->preConditions->next->type, manifest->preConditions->next->value);
    printf("POSTCOND: %d %s\n", manifest->postConditions->type, manifest->postConditions->value);
    printf("CONTENT KEY METHOD: %d\n", manifest->contentKeyMethod);
    printf("FORMAT: %d SIZE: %d STORAGE: %d\n", manifest->payloadInfo->format, manifest->payloadInfo->size, manifest->payloadInfo->storage);
    printf("URL: %s DIGEST: %s\n", manifest->payloadInfo->URLDigest->URL, manifest->payloadInfo->URLDigest->digest);
    printf("PRECURSORS: %s %s\n", manifest->precursorImage->URL, manifest->precursorImage->digest);
    printf("DEPENDENCIES: %s %s\n", manifest->dependencies->URL, manifest->dependencies->digest);
    printf("OPTIONS: %d %s\n", manifest->options->type, manifest->options->value);
}