#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *manifest_buffer = "{\"0\":1,\"1\":\"1553762654\",\"2\":"; //[{\"0\":0,\"1\":\"4be0643f-1d98-573b-97cd-ca98a65347dd\"},{\"0\":1,\"1\":\"18ce9adf-9d2e-57a3-9374-076282f3d95b\"}],\"3\":[],\"4\":0,\"5\":{\"0\":1,\"1\":184380,\"2\":0,\"3\":[{\"0\":\"update/image\",\"1\":\"ac526296b4f53eed4ab337f158afc12755bd046d0982b4fa227ee09897bc32ef\"}]},\"6\":[{}],\"7\":[{}],\"8\":[{}]}";

int get_next_key(char**);
char *get_next_value(char**, char*);
int is_digit(char*);

typedef struct manifest_s {
    int versionID;
    char *sequenceNumber;
    struct condition_t *preConditions;
    struct condition_t *postConditions;
    int contentKeyMethod;
    struct payloadInfo_t *payloadInfo;
    struct URLDigest_t *precursorImage;
    struct URLDigest_t *dependencies;
    struct option_t *options;
} manifest_t;

typedef struct condition_s {
    int type;
    char *value;
    struct condition_t *next;
} condition_t;

typedef struct payloadInfo_s {
    int format;
    int size;
    int storage;
    struct URLDigest_t *URLDigest;
} payloadInfo_t;

typedef struct URLDigest_s {
    char *URL;
    char *digest;
    struct URLDigest_t *next;
} URLDigest_t;

typedef struct option_s {
    int type;
    char *value;
    struct option_t *next;
} option_t;

void main() {
    manifest_t manifest;
    condition_t preConditions;
    condition_t postConditions;
    payloadInfo_t payloadInfo;
    URLDigest_t URLDigest;
    URLDigest_t precursorImage;
    URLDigest_t dependencies;
    option_t options;

    char *cur_pos = manifest_buffer;
    int key;
    char ret[2];
    while(*cur_pos != '\0') {
        key = get_next_key(&cur_pos);        

        switch(key) {
            case 0:
                get_next_value(&cur_pos, ret);
                printf("RETTT: %s\n", ret);
                break;
            case 1:
                manifest.sequenceNumber = get_next_value(&cur_pos, ret);
                printf("SEQ: %s\n", manifest.sequenceNumber);
                break;
        }
    }
}

int get_next_key(char **buffer) {
    //char *buffer = *pos;
    printf("Starting at %c\n", **buffer);
    char check; // Will hold the candidate for the key value
    while(**buffer != '\0') {
        printf("Scanning %c%c%c\n", **buffer, *(*buffer+1), *(*buffer+2));
        check = (*buffer)[1];
        //printf("Is %c digit? %s len %ld\n", check, is_digit(&check) ? "Yes" : "No", strlen(&check));

        // Check for the pattern "X" where X is a digit
        if(**buffer == '"' && is_digit(&check) && *(*buffer + 2) == '"') {
            printf("Found %c%c%c\n", **buffer, *(*buffer + 1), *(*buffer + 2));
            //printf("Buffer: %p\n", (void *)*buffer);
            // Advance the buffer past the current key, to the value (skipping the :)
            (*buffer) += 4;
            return atoi(&check);
        } else {
            (*buffer)++;
        }
    }
}

char *get_next_value(char **buffer, char *ret) {
    // Distance until end of value (comma separation)
    int distance = strchr(*buffer, ',') - *buffer;
    printf("Ret: %s\n", ret);
    printf("BUFFER %s\n", *buffer);
    printf("DISTANCE %d\n", distance);
    // Copy the value field
    strncpy(ret, *buffer, distance);
    ret[distance] = 0;
    printf("Val: %s\n", ret);
}


int is_digit(char *c) {
    while(*c != '\0')
    {
        if(*c < '0' || *c > '9')
            return 0;
        c++;
    }
    return 1;
}