# "An Internet of Things Software and Firmware Update Architecture Based on the SUIT Specification" project directory

## Files

* update-client.c: The client. It registers to the server, requests a manifest and parses it, requests image data and calculates its checksum.
* update-server.c: Registers the resources.
* resources/res-register.c: Parses client information and creates a device profile.
* resources/res-manifest.c: Encodes, encrypts, and sends the manifest used in the experiments.
* resources/res-image.c: Encodes and encrypts generated data block by block.

PRELIMINARIES
-------------

- Two Firefly boards, one for the client and one for the server.
- The Contiker docker image.

 HOWTO
------------

* Connect the Firefly boards, make sure they are connected to /dev/ttyUSB0 and /dev/ttyUSB1 (or change the run scripts).
* Execute run-server.sh and run-client.sh.

DETAILS
-------

- Manifests are encrypted and decrypted all at once. Generated image data is encrypted and decrypted per CoAP block. COSE encryption adds 8 bytes of tag, meaning the ciphertext buffers must be 8 bytes larger than the plaintext buffers.
- The client sends its credentials to the server as an URI-query. Disabling SICSLOWPAN_CONF_FRAG or reducing COAP_MAX_HEADER_SIZE in project-conf.h will require blockwise transfers from client to server instead, which is not solved.

TODOs
-----

- Generalize parser.
- Thoroughly test parser.
- Reduce memory usage of parser.
- Setting DEBUG 1 (in general, printing a lot) in update-client.c re-orders stack so that the client might crash.
