CFLAGS := -std=c11 \
	-Wall -Wextra -pedantic \
	-Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes \
	-D_GNU_SOURCE \
	$(CFLAGS)

LDLIBS = -lpcap -ljansson

all: esldump

clean:
	$(RM) esldump *.o

.PHONY: clean
