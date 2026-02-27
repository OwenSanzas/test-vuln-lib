CC = gcc
CFLAGS = -Wall -Wextra -fPIC

all: libvuln.so

libvuln.so: vuln_lib.o
	$(CC) -shared -o $@ $^

vuln_lib.o: vuln_lib.c vuln_lib.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o *.so

.PHONY: all clean
