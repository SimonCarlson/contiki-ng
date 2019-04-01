#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *manifest_buffer = "{\"0\":0, \"1\": 123456, \"2\": [{\"0\": 0, \"1\": \"4be0643f-1d98-573b-97cd-ca98a65347dd\"}, {\"0\": 1, \"1\": \"18ce9adf-9d2e-57a3-9374-076282f3d95b\"}], \"3\": []}"; //, \"4\": 0, \"5\": {\"0\": 1, \"1\": 184380, \"2\": 0, \"3\": [{\"0\": \"update/image\", \"1\": \"ac526296b4f53eed4ab337f158afc12755bd046d0982b4fa227ee09897bc32ef\"}]}, \"6\": [{}], \"7\": [{}], \"8\": [{}]}";

int get_next_key(char**);
char *get_next_value(char**);
int is_digit(char*);

typedef struct manifest_s {
    int versionID;
    int sequenceNumber;
    struct condition_s *preConditions;
    struct condition_s *postConditions;
    int contentKeyMethod;
    struct payloadInfo_s *payloadInfo;
    struct URLDigest_s *precursorImage;
    struct URLDigest_s *dependencies;
    struct option_s *options;
} manifest_t;

typedef struct condition_s {
    int type;
    char value[50];
    struct condition_s *next;
} condition_t;

typedef struct payloadInfo_s {
    int format;
    int size;
    int storage;
    struct URLDigest_s *URLDigest;
} payloadInfo_t;

typedef struct URLDigest_s {
    char *URL;
    char *digest;
    struct URLDigest_s *next;
} URLDigest_t;

typedef struct option_s {
    int type;
    char *value;
    struct option_s *next;
} option_t;

void main() {
    manifest_t manifest;
    condition_t preConditions;
    preConditions.type = -1;
    condition_t postConditions;
    payloadInfo_t payloadInfo;
    URLDigest_t URLDigest;
    URLDigest_t *precursorImage;
    URLDigest_t *dependencies;
    option_t *options;

    char *cur_pos = manifest_buffer;
    int key;
    char *ret;
    while(*cur_pos != '\0' && strlen(cur_pos) != 0) {
        //printf("%s\n", cur_pos);
        key = get_next_key(&cur_pos);
        switch(key) {
            case 0:
                // VERSION ID
                ret = get_next_value(&cur_pos);
                manifest.versionID = atoi(ret);
                break;
            case 1:
                // SEQUENCE NUMBER
                ret = get_next_value(&cur_pos);
                manifest.sequenceNumber = atoi(ret);
                break;
            case 2:
                key = get_next_key(&cur_pos);
                ret = get_next_value(&cur_pos);
                printf("1. Key: %d. Value: %s\n", key, ret);
                key = get_next_key(&cur_pos);
                ret = get_next_value(&cur_pos);
                printf("2. Key: %d. Value: %s\n", key, ret);

                key = get_next_key(&cur_pos);
                ret = get_next_value(&cur_pos);
                printf("1. Key: %d. Value: %s\n", key, ret);
                key = get_next_key(&cur_pos);
                ret = get_next_value(&cur_pos);
                printf("2. Key: %d. Value: %s\n", key, ret);
                break;
            case 3:
                ret = get_next_value(&cur_pos);
                break;
            default:
                break;
        }
        printf("3. Key: %d. Value: %s\n", key, ret);      
    
    printf("VERSION: %d\n", manifest.versionID);
    printf("SEQUENCE: %d\n", manifest.sequenceNumber);
    }
}

int get_next_key(char **buffer) {
    //char *buffer = *pos;
    //printf("Starting at %c\n", **buffer);
    char check; // Will hold the candidate for the key value
    while(**buffer != '\0') {
        //printf("Scanning %c%c%c\n", **buffer, *(*buffer+1), *(*buffer+2));
        check = (*buffer)[1];
        //printf("Is %c digit? %s len %ld\n", check, is_digit(&check) ? "Yes" : "No", strlen(&check));

        // Check for the pattern "X" where X is a digit
        if(**buffer == '"' && is_digit(&check) && *(*buffer + 2) == '"') {
            //printf("Found %c%c%c\n", **buffer, *(*buffer + 1), *(*buffer + 2));
            //printf("Buffer: %p\n", (void *)*buffer);
            // Advance the buffer past the current key, to the value (skipping the ':')
            // TODO: Increment with distance to next space + 1
            (*buffer) += 4;
            return atoi(&check);
        } else {
            (*buffer)++;
        }
    }
}

char *get_next_value(char **buffer) {
    // Distance until end of value (comma separation)
    char *index = strchr(*buffer, ',');
    int distance;
    // Index == NULL means no comma found, string approaching its end
    // Search instead for closing bracket '}'
    if(index == NULL) {
        index = strchr(*buffer, '}');
    }
    distance = index - *buffer;

    // TODO: Memory allocation for Contiki
    char *ret = malloc(distance+1);
    // Copy the value field
    strncpy(ret, *buffer, distance);
    //printf("RET1: %s\n", ret);
    char *mark = strchr(ret, '"');
    if(mark != NULL) {
        ret += mark - ret + 1;
        //printf("RET2: %s\n", ret);
        mark = strchr(ret, '"');
        ret[mark - ret] = '\0';
        //printf("RET3: %s\n", ret);
    } else {
        // Null terminate
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