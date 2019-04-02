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
    char *value;
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

void manifest_parser(manifest_t**);
int get_next_key(char**);
char *get_next_value(char**);
int is_digit(char*);
void print_manifest(manifest_t*);