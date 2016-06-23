CFLAGS=-I$(SSL_PREFIX)/include
LDFLAGS=-Wl,-rpath,$(SSL_PREFIX)/lib -L $(SSL_PREFIX)/lib -lssl -lcrypto -ldl -lm
DECRYPT_OBJS=drown.o oracle.o trimmers.o decrypt.o utils.o
TRIMMABLE_OBJS=trimmable.o oracle.o trimmers.o decrypt.o utils.o

all: decrypt trimmable

decrypt: $(DECRYPT_OBJS)
	gcc -g -o $@ $^ $(LDFLAGS)

trimmable: $(TRIMMABLE_OBJS)
	gcc -g -o $@ $^ $(LDFLAGS)

%.o: %.c
	gcc -g -c -o $@ $^ $(CFLAGS)

clean:
	rm -f decrypt trimmable $(DECRYPT_OBJS) $(TRIMMABLE_OBJS)
