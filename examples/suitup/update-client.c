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
#include "sys/energest.h"
#include "manifest-parser.h"
#include "opt-cose.h"
#include "os/net/security/tinydtls/tinydtls.h"
#include "os/net/security/tinydtls/sha2/sha2.h"

/* Log configuration */
#include "coap-log.h"
#define LOG_MODULE "client"
#define LOG_LEVEL  LOG_LEVEL_COAP

#define SERVER_EP "coap://[fd00::212:4b00:9df:9096]"
#define VENDOR_ID "4be0643f-1d98-573b-97cd-ca98a65347dd"
#define CLASS_ID "18ce9adf-9d2e-57a3-9374-076282f3d95b"
#define VERSION "1.0"
#define INTERVAL 3
#define TIMEOUT 1

#define DEBUG 0
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINTF_HEX(data, len) 	printf_hex(data, len)
#define PRINTF_CHAR(data, len) printf_char(data, len)
#else
#define PRINTF(...)
#define PRINTF_HEX(data, len)
#define PRINTF_CHAR(data, len)
#endif

void printf_char(unsigned char*, unsigned int);
void printf_hex(unsigned char*, unsigned int);

static char manifest_buffer[370];
static int manifest_offset = 0;
static int blocks = 0;
dtls_sha256_ctx ctx;

struct value_t {
    char value[256];        // Digest is SHA-256, needs to fit
};

// TODO: Why does it not work with blocks = 1 and freeing the memory?
#define BLOCKS 6
MEMB(manifestValue, struct value_t, BLOCKS);

PROCESS(update_client, "Update client");
AUTOSTART_PROCESSES(&update_client);

void printf_char(unsigned char *data, unsigned int len){
	unsigned int i;
	for(i = 0; i < len - 1; i+=2)
	{
		printf("%c%c ", data[i], data[i+1]);
	}
	printf("\n");
}

void printf_hex(unsigned char *data, unsigned int len){
	unsigned int i;
	for(i = 0; i < len; i++)
	{
		printf("%02x ",data[i]);
	}
	printf("\n");
}

void register_callback(coap_message_t *response) {
    PRINTF("REGISTER CALLBACK\n");
}

void manifest_callback(coap_message_t *response) {
    PRINTF("MANIFEST CALLBACK\n");
    const uint8_t *chunk;

    coap_get_payload(response, &chunk);
    PRINTF("RECEIVED: ");
    for(int i = 0; i < 32; i++) {
        PRINTF("%02x ", chunk[i]);
    }
    PRINTF("\n");
    // Reassemble the received ciphertext into a buffer
    memcpy(manifest_buffer + manifest_offset, (char *)chunk, 32);
    manifest_offset += 32;
}

void image_callback(coap_message_t *response) {
    PRINTF("IMAGE CALLBACK\n");
    const uint8_t *chunk;

    coap_get_payload(response, &chunk);
    PRINTF("RECEIVED: ");
    for(int i = 0; i < 32; i++) {
        PRINTF("%02x ", chunk[i]);
    }
    PRINTF("\n");

    opt_cose_encrypt_t decrypt;
    char *aad2 = "0011bbcc22dd44ee55ff660077";
    uint8_t key2[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t buffer2 = 0;
    uint8_t nonce[7] = {0, 1, 2, 3, 4, 5, 6};	
    uint8_t decrypt_buffer2[24];
    uint8_t cipher[32];

    // Decrypt each block
    memcpy(cipher, chunk, 32);
    OPT_COSE_Init(&decrypt);
    OPT_COSE_SetAlg(&decrypt, COSE_Algorithm_AES_CCM_64_64_128);
    OPT_COSE_SetNonce(&decrypt, nonce, 7);
    OPT_COSE_SetAAD(&decrypt, (uint8_t*)aad2, strlen(aad2));
    OPT_COSE_SetContent(&decrypt, decrypt_buffer2, 24);
    OPT_COSE_SetCiphertextBuffer(&decrypt, (uint8_t*)cipher, 32);
    OPT_COSE_Decode(&decrypt, &buffer2, 1);
    OPT_COSE_Decrypt(&decrypt, key2, 16);

    PRINTF("plaintext: ");
    for(int j = 0; j < 24; j++) {
        PRINTF("%c", decrypt.plaintext[j]);
    }
    PRINTF("\n");
    
    // Last block might have less than 24 bytes of data
    int length = strlen((char *)decrypt.plaintext) < 24 ? strlen((char *)decrypt.plaintext) : 24;
    dtls_sha256_update(&ctx, decrypt.plaintext, length);

    blocks++;
    if(blocks % 100 == 0) {
        printf("Block %d\n", blocks);
    }
}

int manifest_checker(manifest_t *manifest) {
    // Check pre conditions, directives in options etc
    // Here you can implement custom checking for your deployment
    if(strcmp(manifest->preConditions->value, VENDOR_ID) != 0) {
        PRINTF("Mismatched vendor ID.\n");
        return 0;
    }

    if(strcmp(manifest->preConditions->next->value, CLASS_ID) != 0) {
        PRINTF("Mismatched class ID.\n");
        return 0;
    }

    return 1;
}

PROCESS_THREAD(update_client, ev, data) {
    PROCESS_BEGIN();
    printf("Client started.\n");
    static struct etimer et;
    static coap_endpoint_t server_ep;
    static coap_message_t request[1];      /* This way the packet can be treated as pointer as usual. */
    char query_data[90];

    coap_engine_init();
    coap_keystore_simple_init();
    coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
    
    // Connect to server endpoint
    coap_endpoint_connect(&server_ep);
    while(!coap_endpoint_is_connected(&server_ep)) {
        etimer_set(&et, CLOCK_SECOND * INTERVAL);
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
        printf("Checking connection again.\n");
        coap_endpoint_connect(&server_ep);
    }
    printf("Client connected.\n");

    // Register to well-known endpoint update/register
    coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
    coap_set_header_uri_path(request, "update/register");
    // Copy POST data into buffer for server to make profile of
    snprintf(query_data, sizeof(query_data) - 1, "?vid=%s&cid=%s&v=%s", VENDOR_ID, CLASS_ID, VERSION);
    coap_set_header_uri_query(request, query_data); 
    // Register to server
    COAP_BLOCKING_REQUEST(&server_ep, request, register_callback);
    printf("Registration done.\n");

    // Get manifest from well known endpoint update/manifest
    coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
    coap_set_header_uri_path(request, "update/manifest");
    COAP_BLOCKING_REQUEST(&server_ep, request, manifest_callback);
    printf("Manifest received.\n");

    // For comparison with ciphertext hex data on server side
    PRINTF("Ciphertext manifest: \n");
    PRINTF_HEX((uint8_t*)manifest_buffer, 330);
    PRINTF("\n");

    // Decode and decrypt manifest into plaintext
    opt_cose_encrypt_t decrypt;
	char *aad2 = "0011bbcc22dd44ee55ff660077";
	uint8_t decrypt_buffer[325];
	uint8_t key2[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	uint8_t buffer2 = 0;
    uint8_t nonce[7] = {0, 1, 2, 3, 4, 5, 6};	
    
	OPT_COSE_Init(&decrypt);
	OPT_COSE_SetAlg(&decrypt, COSE_Algorithm_AES_CCM_64_64_128);
	OPT_COSE_SetNonce(&decrypt, nonce, 7);
	OPT_COSE_SetAAD(&decrypt, (uint8_t*)aad2, strlen(aad2));
	OPT_COSE_SetContent(&decrypt, decrypt_buffer, 324);
	OPT_COSE_SetCiphertextBuffer(&decrypt, (uint8_t*)manifest_buffer, 332);
	OPT_COSE_Decode(&decrypt, &buffer2, 1);
	OPT_COSE_Decrypt(&decrypt, key2, 16);
    // Null-terminate plaintext
    decrypt_buffer[324] = 0;

    printf("PLAINTEXT: %s\n", decrypt.plaintext);
    // For comparison with plaintext hex data on server side
    PRINTF("PLAINTEXT HEX:\n");
    PRINTF_HEX(decrypt.plaintext, decrypt.plaintext_len);
    PRINTF("\n");

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
    PRINTF("Accept: %d\n", accept);
    
    if(accept) {
        printf("Manifest accepted.\n");
        // Initialize global has context before updating it in callback function
        dtls_sha256_init(&ctx);
        // Get image from server
        coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
        // Image endpoint is not well known, use URL specified in manifest
        coap_set_header_uri_path(request, manifest.payloadInfo->URLDigest->URL);
        COAP_BLOCKING_REQUEST(&server_ep, request, image_callback);
        printf("Image data received.\n");
        printf("%d blocks received during image transfer.\n", blocks);

	    uint8_t chksum[DTLS_SHA256_DIGEST_LENGTH];
        // Calculate checksum
	    dtls_sha256_final(chksum, &ctx);
	    printf("Calculated checksum:\n");
	    printf_hex(chksum, DTLS_SHA256_DIGEST_LENGTH);
    } else {
        printf("Mismatched manifest.\n");
    }

    printf("Finished.\n");

  PROCESS_END();
}

void manifest_parser(manifest_t *manifest_p, char *manifest_string) {
    char *cur_pos = manifest_string;
    uint8_t key;
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
                break;
            case 1:
                // SEQUENCE NUMBER
                val = get_next_value(&cur_pos);
                manifest_p->sequenceNumber = atoi(val);
                memb_free(&manifestValue, val);
                break;
            case 2:
                // PRECONDITIONS
                // First pair (vendor id)
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->preConditions->type = atoi(val);
                memb_free(&manifestValue, val);
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->preConditions->value = val;
                memb_free(&manifestValue, val);

                // Second pair (class id)
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->preConditions->next->type = atoi(val);
                memb_free(&manifestValue, val);
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->preConditions->next->value = val;
                memb_free(&manifestValue, val);
                break;
            case 3:
                // POSTCONDITIONS
                val = get_next_value(&cur_pos);
                manifest_p->postConditions->type = -1;
                manifest_p->postConditions->value = NULL;
                manifest_p->postConditions->next = NULL;
                memb_free(&manifestValue, val);
                break;
            case 4:
                // CONTENT KEY METHOD
                val = get_next_value(&cur_pos);
                manifest_p->contentKeyMethod = atoi(val);
                memb_free(&manifestValue, val);
                break;
            case 5:
                // PAYLOAD INFO
                // Format
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->payloadInfo->format = atoi(val);
                memb_free(&manifestValue, val);

                // Size
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->payloadInfo->size = atoi(val);
                memb_free(&manifestValue, val);

                // Storage
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->payloadInfo->storage = atoi(val);
                memb_free(&manifestValue, val);

                // Start of URLDigest, skip its key
                get_next_key(&cur_pos);
                // URL
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->payloadInfo->URLDigest->URL = val;
                memb_free(&manifestValue, val);

                // DIGEST
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                manifest_p->payloadInfo->URLDigest->digest = val;
                memb_free(&manifestValue, val);

                manifest_p->payloadInfo->URLDigest->next = NULL;
                break;
            case 6:
                // PRECURSORS
                val = get_next_value(&cur_pos);
                manifest_p->precursorImage->URL = NULL;
                manifest_p->precursorImage->digest = NULL;
                manifest_p->precursorImage->next = NULL;
                memb_free(&manifestValue, val);
                break;
            case 7:
                // DEPENDENCIES
                val = get_next_value(&cur_pos);
                manifest_p->dependencies->URL = NULL;
                manifest_p->dependencies->digest = NULL;
                manifest_p->dependencies->next = NULL;
                memb_free(&manifestValue, val);
                break;
            case 8:
                // OPTIONS
                val = get_next_value(&cur_pos);
                manifest_p->options->type = -1;
                manifest_p->options->value = NULL;
                manifest_p->options->next = NULL;
                memb_free(&manifestValue, val);
                break;
        }     
    
    }
}

uint8_t get_next_key(char **buffer) {
    char check; // Will hold the candidate for the key value

    while(**buffer > 0) {
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

uint8_t is_digit(char *c) {
    if(*c < '0' || *c > '9') {
        return 0;
    } else {
        return 1;
    }
}

void print_manifest(manifest_t *manifest) {
    PRINTF("VERSION: %d\n", manifest->versionID);
    PRINTF("SEQUENCE: %ld\n", manifest->sequenceNumber);
    PRINTF("PRECOND 1: %d %s\n", manifest->preConditions->type, manifest->preConditions->value);
    PRINTF("PRECOND 2: %d %s\n", manifest->preConditions->next->type, manifest->preConditions->next->value);
    PRINTF("POSTCOND: %d %s\n", manifest->postConditions->type, manifest->postConditions->value);
    PRINTF("CONTENT KEY METHOD: %d\n", manifest->contentKeyMethod);
    PRINTF("FORMAT: %d SIZE: %ld STORAGE: %d\n", manifest->payloadInfo->format, manifest->payloadInfo->size, manifest->payloadInfo->storage);
    PRINTF("URL: %s DIGEST: %s\n", manifest->payloadInfo->URLDigest->URL, manifest->payloadInfo->URLDigest->digest);
    PRINTF("PRECURSORS: %s %s\n", manifest->precursorImage->URL, manifest->precursorImage->digest);
    PRINTF("DEPENDENCIES: %s %s\n", manifest->dependencies->URL, manifest->dependencies->digest);
    PRINTF("OPTIONS: %d %s\n", manifest->options->type, manifest->options->value);
}
