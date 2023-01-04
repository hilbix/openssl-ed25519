# This Works is placed under the terms of the Copyright Less License,
# see file COPYRIGHT.CLL.  USE AT OWN RISK, ABSOLUTELY NO WARRANTY.

BINS=sig
KEYS=.privkey.pem
CFLAGS=-Wall -O3 -g -Wno-unused-function
LDLIBS=$(shell pkg-config --libs openssl)

.PHONY:	love
love:	all

.PHONY:	all
all:	$(BINS) .privkey.pem

.PHONY:	clean
clean:
	rm -f $(BINS)

$(KEYS):
	openssl genpkey -algorithm ed25519 -out '$@'

.PHONY:	test
test: $(BINS) .pubkey.pem
	date >> example.txt
	./sig example.txt .pubkey.pem .privkey.pem >> example.txt
	./sig example.txt .pubkey.pem && echo signature OK

.pubkey.pem:	.privkey.pem
	openssl pkey -in '$<' -pubout -out '$@'

