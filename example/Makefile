#
# Example of using library
#
LDFLAGS += -lurlparser
CFLAGS = -I../src -L../src

.PHONY: example

all: example
	./example "http://hello.com:8899/index.php?q=letto#wello"
	./example # usage output

example: example.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)
