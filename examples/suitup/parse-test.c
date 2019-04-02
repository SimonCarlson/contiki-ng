#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "parse-test.h"

char *manifest_buffer = "{\"0\": 1, \"1\": 1554114615, \"2\": [{\"0\": 0, \"1\": \"4be0643f-1d98-573b-97cd-ca98a65347dd\"}, {\"0\": 1, \"1\": \"18ce9adf-9d2e-57a3-9374-076282f3d95b\"}], \"3\": [], \"4\": 0, \"5\": {\"0\": 1, \"1\": 184380, \"2\": 0, \"3\": [{\"0\": \"update/image\", \"1\": \"ac526296b4f53eed4ab337f158afc12755bd046d0982b4fa227ee09897bc32ef\"}]}, \"6\": [], \"7\": [], \"8\": []}";

void main() {
    manifest_t *manifest;
    condition_t preConditions;
    condition_t nextPreCondition;
    condition_t postConditions;
    payloadInfo_t payloadInfo;
    URLDigest_t URLDigest;
    URLDigest_t precursorImage;
    URLDigest_t dependencies;
    option_t options;

    preConditions.next = &nextPreCondition;
    manifest->preConditions = &preConditions;
    manifest->postConditions = &postConditions;
    payloadInfo.URLDigest = &URLDigest;
    manifest->payloadInfo = &payloadInfo;
    manifest->precursorImage = &precursorImage;
    manifest->dependencies = &dependencies;
    manifest->options = &options;

    manifest_parser(&manifest, manifest_buffer);
    print_manifest(manifest);
}

void print_manifest(manifest_t *manifest) {
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

void manifest_parser(manifest_t **manifest_p, char *manifest_string) {
    char *cur_pos = manifest_string;
    int key;
    char *val;
    // Traverse the manifest
    while(*cur_pos != '\0') {
        key = get_next_key(&cur_pos);
        switch(key) {
            case 0:
                // VERSION ID
                printf("Version ID!\n");
                val = get_next_value(&cur_pos);
                (*manifest_p)->versionID = atoi(val);
                free(val);
                break;
            case 1:
                // SEQUENCE NUMBER
                printf("Sequence number!\n");
                val = get_next_value(&cur_pos);
                (*manifest_p)->sequenceNumber = atoi(val);
                free(val);
                break;
            case 2:
                // PRECONDITIONS
                // First pair (vendor id)
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                (*manifest_p)->preConditions->type = atoi(val);
                free(val);
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                (*manifest_p)->preConditions->value = val;
                //free(val);

                // Second pair (class id)
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                (*manifest_p)->preConditions->next->type = atoi(val);
                free(val);
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                (*manifest_p)->preConditions->next->value = val;
                //free(val);

                //preConditions.next = &nextPreCondition;
                //(*manifest_p)->preConditions = &preConditions;
                break;
            case 3:
                // POSTCONDITIONS
                val = get_next_value(&cur_pos);
                free(val);
                (*manifest_p)->postConditions->type = -1;
                (*manifest_p)->postConditions->value = NULL;
                (*manifest_p)->postConditions->next = NULL;
                //(*manifest_p)->postConditions = &postConditions;
                break;
            case 4:
                // CONTENT KEY METHOD
                val = get_next_value(&cur_pos);
                (*manifest_p)->contentKeyMethod = atoi(val);
                free(val);
                break;
            case 5:
                // PAYLOAD INFO
                // Format
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                (*manifest_p)->payloadInfo->format = atoi(val);
                free(val);

                // Size
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                (*manifest_p)->payloadInfo->size = atoi(val);
                free(val);

                // Storage
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                (*manifest_p)->payloadInfo->storage = atoi(val);
                free(val);

                // Start of URLDigest, skip its key
                get_next_key(&cur_pos);
                // URL
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                (*manifest_p)->payloadInfo->URLDigest->URL = val;
                //free(val);

                // digest
                key = get_next_key(&cur_pos);
                val = get_next_value(&cur_pos);
                (*manifest_p)->payloadInfo->URLDigest->digest = val;
                //free(val);

                (*manifest_p)->payloadInfo->URLDigest->next = NULL;
                //payloadInfo.URLDigest = &URLDigest;
                //(*manifest_p)->payloadInfo = &payloadInfo;
                break;
            case 6:
                // PRECURSORS
                val = get_next_value(&cur_pos);
                free(val);
                (*manifest_p)->precursorImage->URL = NULL;
                (*manifest_p)->precursorImage->digest = NULL;
                (*manifest_p)->precursorImage->next = NULL;
                //(*manifest_p)->precursorImage = &precursorImage;
                break;
            case 7:
                // DEPENDENCIES
                val = get_next_value(&cur_pos);
                free(val);
                (*manifest_p)->dependencies->URL = NULL;
                (*manifest_p)->dependencies->digest = NULL;
                (*manifest_p)->dependencies->next = NULL;
                //(*manifest_p)->dependencies = &dependencies;
                break;
            case 8:
                // OPTIONS
                val = get_next_value(&cur_pos);
                free(val);
                (*manifest_p)->options->type = -1;
                (*manifest_p)->options->value = NULL;
                (*manifest_p)->options->next = NULL;
                //(*manifest_p)->options = &options;
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

    // TODO: Memory allocation for Contiki
    char *ret = malloc(distance+1);
    // Copy the value field
    strncpy(ret, *buffer, distance);
    // Check if there is a citation mark (value is in string format)
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