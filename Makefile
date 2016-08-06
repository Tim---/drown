CFLAGS=-I$(SSL_PREFIX)/include -O3
#CFLAGS=-I$(SSL_PREFIX)/include -g
LDFLAGS=-Wl,-rpath,$(SSL_PREFIX)/lib -L $(SSL_PREFIX)/lib -lssl -lcrypto -ldl -lm -lpthread
DECRYPT_OBJS=drown.o oracle.o trimmers.o decrypt.o utils.o
TRIMMABLE_OBJS=trimmable.o oracle.o trimmers.o decrypt.o utils.o

all: decrypt trimmable

decrypt: $(DECRYPT_OBJS)
	gcc -o $@ $^ $(LDFLAGS)

trimmable: $(TRIMMABLE_OBJS)
	gcc -o $@ $^ $(LDFLAGS)

%.o: %.c
	gcc -c -o $@ $^ $(CFLAGS)

clean:
	rm -f decrypt trimmable $(DECRYPT_OBJS) $(TRIMMABLE_OBJS)
