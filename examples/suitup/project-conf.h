/**
 * \file
 *      Software updates example project configuration
 * \author
 *      Simon Carlson <scarlso@kth.se>
 */

#ifndef IOT_UPDATES_PROJECT_CONF
#define IOT_UPDATES_PROJECT_CONF

/* Increase rpl-border-router IP-buffer when using more than 64. */
#define COAP_MAX_CHUNK_SIZE           48

/* Estimate your header size, especially when using Proxy-Uri. */
#define COAP_MAX_HEADER_SIZE          128

/* Multiplies with chunk size, be aware of memory constraints. */
#ifndef COAP_MAX_OPEN_TRANSACTIONS
#define COAP_MAX_OPEN_TRANSACTIONS     1
#endif /* COAP_MAX_OPEN_TRANSACTIONS */

/* Must be <= open transactions, default is COAP_MAX_OPEN_TRANSACTIONS-1. */
#define COAP_CONF_MAX_OBSERVEES             0

/* Filtering .well-known/core per query can be disabled to save space. */
#define COAP_LINK_FORMAT_FILTERING     0
#define COAP_PROXY_OPTION_PROCESSING   0

/* Enable client-side support for COAP observe */
#ifndef COAP_OBSERVE_CLIENT
#define COAP_OBSERVE_CLIENT            0
#endif /* COAP_OBSERVE_CLIENT */

#define COAP_DTLS_PSK_DEFAULT_IDENTITY "user"
#define COAP_DTLS_PSK_DEFAULT_KEY "pass"

#define QUEUEBUF_CONF_NUM 3
#define NBR_TABLE_CONF_MAX_NEIGHBORS 2
#define NETSTACK_MAX_ROUTE_ENTIRES 2
#define SICSLOWPAN_CONF_FRAG 1
#define UIP_CONF_BUFFER_SIZE 280

#endif /* IOT_UPDATES_PROJECT_CONF */
