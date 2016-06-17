CFLAGS=-I$(SSL_PREFIX)/include
LDFLAGS=-Wl,-rpath,$(SSL_PREFIX)/lib -L $(SSL_PREFIX)/lib -lssl -lcrypto -ldl -lm
OBJS=drown.o oracle.o trimmers.o decrypt.o

drown: $(OBJS)
	gcc -g -o $@ $^ $(LDFLAGS)

%.o: %.c
	gcc -g -c -o $@ $^ $(CFLAGS)

clean:
	rm drown $(OBJS)
