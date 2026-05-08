CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap

BIN = security-suite
SRCS = analyzer.c utils.c
HDR = analyzer.h utils.h

PCAP_FILE = traffic.pcap
IP = 192.168.153.1

all: $(BIN)

$(BIN): $(SRCS) $(HDR)
	$(CC) $(CFLAGS) -o $(BIN) $(SRCS) $(LDFLAGS)

run: all
	./$(BIN) --analyze $(PCAP_FILE) $(IP)

clean:
	rm -f $(BIN) *.o