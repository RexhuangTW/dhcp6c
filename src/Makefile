#
# Makefile for the hello example package
#

CFLAGS+=$(TARGET_CFLAGS)

all: dhcp6c

dhcp6c: dhcp6c.o
	$(CC) -o $@ $^ $(LDFLAGS)
%.o: %.c 
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f dhcp6c *.o

