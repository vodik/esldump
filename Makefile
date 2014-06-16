CFLAGS := -std=c11 \
	-Wall -Wextra -pedantic \
	-Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes \
	-D_GNU_SOURCE \
	$(CFLAGS)

LDLIBS = -lpcap -ljansson

all: esl_pcap_trace

clean:
	$(RM) esl_pcap_trace *.o

.PHONY: clean