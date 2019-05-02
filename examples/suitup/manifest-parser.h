typedef struct manifest_s {
    uint8_t versionID;
    uint32_t sequenceNumber;
    struct condition_s *preConditions;
    struct condition_s *postConditions;
    uint8_t contentKeyMethod;
    struct payloadInfo_s *payloadInfo;
    struct URLDigest_s *precursorImage;
    struct URLDigest_s *dependencies;
    struct option_s *options;
} manifest_t;

typedef struct condition_s {
    int8_t type;
    char *value;
    struct condition_s *next;
} condition_t;

typedef struct payloadInfo_s {
    uint8_t format;
    uint32_t size;
    uint8_t storage;
    struct URLDigest_s *URLDigest;
} payloadInfo_t;

typedef struct URLDigest_s {
    char *URL;
    char *digest;
    struct URLDigest_s *next;
} URLDigest_t;

typedef struct option_s {
    int8_t type;
    char *value;
    struct option_s *next;
} option_t;

void manifest_parser(manifest_t*, char*);
uint8_t get_next_key(char**);
char *get_next_value(char**);
uint8_t is_digit(char*);
void print_manifest(manifest_t*);