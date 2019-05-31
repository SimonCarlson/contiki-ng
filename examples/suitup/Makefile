all: update-server update-client bare-bones
# use target "plugtest-server" explicitly when required

CONTIKI=../..

# build RESTful resources
include $(CONTIKI)/Makefile.identify-target
ifeq ($(TARGET),native)
	MODULES_REL += ./resources-plugtest
endif
MODULES_REL += ./resources
MODULES_REL += $(TARGET)

# Include the CoAP implementation
MODULES += os/net/app-layer/coap
PROJECT_SOURCEFILES += opt-cose.c opt-cbor.c cose-aes-ccm.c
MAKE_WITH_DTLS=1
MAKE_COAP_DTLS_KEYSTORE=MAKE_COAP_DTLS_KEYSTORE_SIMPLE
include $(CONTIKI)/Makefile.include

# border router rules
$(CONTIKI)/tools/tunslip6:	$(CONTIKI)/tools/tunslip6.c
	(cd $(CONTIKI)/tools && $(MAKE) tunslip6)

connect-router:	$(CONTIKI)/tools/tunslip6
	sudo $(CONTIKI)/tools/tunslip6 fd00::1/64

connect-router-cooja:	$(CONTIKI)/tools/tunslip6
	sudo $(CONTIKI)/tools/tunslip6 -a 127.0.0.1 -p 60001 fd00::1/64

connect-router-native:	$(CONTIKI)/examples/rpl-border-router/border-router.native
	sudo $(CONTIKI)/examples/rpl-border-router/border-router.native -a 127.0.0.1 -p 60001 fd00::1/64

connect-native:
	sudo ip address add fdfd::1/64 dev tun0
