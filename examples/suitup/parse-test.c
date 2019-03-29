#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *manifest_buffer = "{\"0\":0, \"1\": 123456, \"2\": [{\"0\": 0, \"1\": \"4be0643f-1d98-573b-97cd-ca98a65347dd\"}, {\"0\": 1, \"1\": \"18ce9adf-9d2e-57a3-9374-076282f3d95b\"}], \"3\": []}"; //, \"4\": 0, \"5\": {\"0\": 1, \"1\": 184380, \"2\": 0, \"3\": [{\"0\": \"update/image\", \"1\": \"ac526296b4f53eed4ab337f158afc12755bd046d0982b4fa227ee09897bc32ef\"}]}, \"6\": [{}], \"7\": [{}], \"8\": [{}]}";

int get_next_key(char**);
void get_next_value(char**, char*);
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
    char ret[256];
    while(*cur_pos != '\0' && strlen(cur_pos) != 0) {
        key = get_next_key(&cur_pos);        

        switch(key) {
            case 0:
                // versionID
                get_next_value(&cur_pos, ret);
                int version_val = atoi(ret);
                manifest.versionID = version_val;
                break;
            case 1:
                // sequenceNumber
                get_next_value(&cur_pos, ret);
                char *seq_val = ret + 1;
                // TODO: Sequence number is no longer encoded as a string, fix formatting
                *(seq_val + strlen(seq_val) - 1) = '\0';
                manifest.sequenceNumber = atoi(seq_val);
                break;
            case 2:
                // preConditions
                printf("Current buffer: %p %s\n", cur_pos, cur_pos);
                condition_t *current;
                //char temp_val[50];
                while(strstr(cur_pos, "}]") - cur_pos > 0) {
                    key = get_next_key(&cur_pos);
                    get_next_value(&cur_pos, ret);
                    current->type = atoi(ret);

                    key = get_next_key(&cur_pos);
                    get_next_value(&cur_pos, ret);
                    memcpy(current->value, ret, strlen(ret));

                    current->next = malloc(sizeof(condition_t));

                    if(preConditions.type == -1) {
                        preConditions = *current;
                    }

                    if(strstr(cur_pos, "}]") - cur_pos > 0) {
                        current = current->next;
                    } else {
                        current->next = NULL;
                    }
                }
                printf("preCond value: %s\n", preConditions.value);
                manifest.preConditions = &preConditions;
                break;
            case 3:
                // postConditions
                get_next_value(&cur_pos, ret);
                postConditions.type = -1;
                postConditions.value[0] = '\0';
                postConditions.next = NULL;
                manifest.postConditions = &postConditions;
                break;
            case 4:
                // contentKeyMethod
                get_next_value(&cur_pos, ret);
                break;
            case 5:
                // payloadInfo
                break;
            case 6:
                // precursorImage
                get_next_value(&cur_pos, ret);
                precursorImage->URL = NULL;
                precursorImage->digest = NULL;
                precursorImage->next = NULL;
                manifest.precursorImage = precursorImage;
                break;
            case 7:
                // dependencies
                get_next_value(&cur_pos, ret);
                dependencies->URL = NULL;
                dependencies->digest = NULL;
                dependencies->next = NULL;
                manifest.dependencies = dependencies;
                break;
            case 8:
                // options
                get_next_value(&cur_pos, ret);
                options->type = -1;
                options->value = NULL;
                options->next = NULL;
                manifest.options = options;
                break;
        }

    //printf("VERSION: %d\n", manifest.versionID);
    //printf("SEQUENCE: %d\n", manifest.sequenceNumber);
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

void get_next_value(char **buffer, char *ret) {
    // Distance until end of value (comma separation)
    char *index = strchr(*buffer, ',');
    int distance;
    // Index == NULL means no comma found, string approaching its end
    // Search instead for closing bracket '}'
    if(index == NULL) {
        index = strchr(*buffer, '}');
    }
    distance = index - *buffer;

    // Copy the value field
    strncpy(ret, *buffer, distance);
    // Advance buffer past the extracted value
    *buffer = *buffer + distance + 1;
    // Null terminate
    ret[distance] = '\0';
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