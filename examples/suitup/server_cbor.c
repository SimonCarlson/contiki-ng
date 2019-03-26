#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>

#include "common.h"
#include <coap2/coap.h>
#include <cbor.h>

static int quit = 0;
static int resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_CON;
const char *keyfile = "/home/samuel/ca/intermediate/private/ocsp.example.com.key.pem";

static void
handle_sigint(int signum) { quit = 1; }

static void
handle_locsp(coap_context_t *ctx,
	     struct coap_resource_t *resource,
	     coap_session_t *session,
	     coap_pdu_t *request,
	     coap_binary_t *token,
	     coap_string_t *query,
	     coap_pdu_t *response) 
{
    if (query == NULL) {
	response->code = COAP_RESPONSE_CODE(404);
	return;
    }

    // Parse LOCSP request.
    uint64_t query_sn;
    uint32_t nonce;
    sscanf(query->s, "%lx&%x", &query_sn, &nonce);

    // Generate LOCSP payload.
    uint64_t locsp_sn;
    uint8_t status = 0;
    cbor_item_t *payload = cbor_new_definite_array(4);
    cbor_array_push(payload, cbor_build_uint64(query_sn));
    cbor_array_push(payload, cbor_build_uint32(nonce));
    cbor_array_push(payload, cbor_build_uint8(status));
    cbor_array_push(payload, cbor_build_uint64(locsp_sn));

    // Serialize reply data.
    uint8_t *payload_buffer;
    size_t bs, payload_length;
    payload_length = cbor_serialize_alloc(payload, &payload_buffer, &bs);
    
    // Sign reply data.
    void *sig_buffer;
    size_t sig_length;
    sign_data(keyfile, payload_buffer, payload_length, &sig_buffer, &sig_length);
    free(payload_buffer);
    //hex_dump(sig_buffer, sig_length);    

    // Serialize concatenated data and signature.
    uint8_t *root_buffer;
    size_t root_length;
    cbor_item_t *root = cbor_new_definite_array(2);
    cbor_array_push(root, payload);
    cbor_array_push(root, cbor_build_bytestring((cbor_data) sig_buffer, sig_length));
    root_length = cbor_serialize_alloc(root, &root_buffer, &bs);

    // Send signed payload.
    coap_add_data_blocked_response(
        resource, session, request, response, token,
        COAP_MEDIATYPE_APPLICATION_CBOR, 1, 
        root_length, root_buffer
    );
    
    // Clean up.
    free(root_buffer);
    cbor_decref(&root);
    cbor_decref(&payload);
}

static void
init_resources(coap_context_t *ctx) 
{
    coap_resource_t *r;
    r = coap_resource_init(coap_make_str_const("locsp"), resource_flags);
    coap_register_handler(r, COAP_REQUEST_GET, handle_locsp);
    coap_add_resource(ctx, r);
}

static void
usage(const char *version) 
{
    char buffer[64];
    fprintf( stderr, "\nlibcoap v%s\n"
        "%s\n\n"
         "Usage: [-k keyfile] [-l loss] [-p port] [-a address]\n"
        "General Options\n"
        "\t-a address\tInterface address to bind to\n"
        "\t-l list\t\tFail to send some datagrams specified by a comma\n"
        "\t       \t\tseparated list of numbers or number ranges\n"
        "\t       \t\t(for debugging only)\n"
        "\t-l loss%%\tRandomly fail to send datagrams with the specified\n"
        "\t       \t\tprobability - 100%% all datagrams, 0%% no datagrams\n"
        "\t       \t\t(for debugging only)\n"
        "\t-p port\t\tListen on specified port\n"
        , version, coap_string_tls_version(buffer, sizeof(buffer)));
}

static coap_context_t *
get_context(const char *node, const char *port) 
{
    coap_context_t *ctx = NULL;
    int s;
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    ctx = coap_new_context(NULL);
    if (!ctx) return NULL;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    s = getaddrinfo(node, port, &hints, &result);
    if ( s != 0 ) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        coap_free_context(ctx);
        return NULL;
    }

    /* iterate through results until success */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        coap_address_t addr;
        coap_endpoint_t *ep_udp = NULL;

        if (rp->ai_addrlen <= sizeof(addr.addr)) {
            coap_address_init(&addr);
            addr.size = rp->ai_addrlen;
            memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);
            if (addr.addr.sa.sa_family != AF_INET)
	        if (addr.addr.sa.sa_family != AF_INET6)
                    goto finish;
            ep_udp = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
            if (!ep_udp) {
                coap_log(LOG_CRIT, "cannot create UDP endpoint\n");
                continue;
            } else {
                goto finish;
            }
        }
    }
    fprintf(stderr, "no context available for interface '%s'\n", node);

    finish:
        freeaddrinfo(result);
        return ctx;
}

int
main(int argc, char **argv) 
{
    coap_context_t  *ctx;
    char addr_str[NI_MAXHOST] = "::";
    char port_str[NI_MAXSERV] = "5683";
    int opt;
    coap_log_t log_level = LOG_WARNING;
    struct sigaction sa;

    while ((opt = getopt(argc, argv, "a:k::l:p:")) != -1) {
        switch (opt) {
            case 'a':
                strncpy(addr_str, optarg, NI_MAXHOST-1);
                addr_str[NI_MAXHOST - 1] = '\0';
                break;
            case 'l':
                if (!coap_debug_set_packet_loss(optarg)) {
	            usage( LIBCOAP_PACKAGE_VERSION );
	            exit(1);
                }
                break;
            case 'p' :
                strncpy(port_str, optarg, NI_MAXSERV-1);
                port_str[NI_MAXSERV - 1] = '\0';
                break;
            default:
                usage( LIBCOAP_PACKAGE_VERSION );
                exit( 1 );
        }
    }

    coap_startup();
    coap_set_log_level(log_level);

    ctx = get_context(addr_str, port_str);
    if (!ctx) return -1;

    init_resources(ctx);

    memset (&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = handle_sigint;
    sa.sa_flags = 0;
    sigaction (SIGINT, &sa, NULL);
    sigaction (SIGTERM, &sa, NULL);

    while ( !quit )
        if (coap_run_once(ctx, 0) < 0) break;

    coap_free_context(ctx);
    coap_cleanup();

    return 0;
}

