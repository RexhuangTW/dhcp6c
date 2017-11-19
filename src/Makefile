#
# Makefile for the dhcp6c
#

CFLAGS+=$(TARGET_CFLAGS)

all: dhcp6c

dhcp6c: dhcp6.o
	$(CC) -o $@ $^ $(LDFLAGS)
%.o: %.c 
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f dhcp6c *.o

