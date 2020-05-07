CC = gcc
LIBS = -lpcap
CFLAGS = -Wall

# synflood: src/synflood.c src/synflood.h
# 	mkdir -p bin/
# 	$(CC) src/synflood.c -o bin/synflood $(CFLAGS) 

main: bin cli sniffer synflood utils
	$(CC) bin/cli.o bin/sniffer.o bin/synflood.o bin/utils.o -o bin/synflood $(LIBS)

bin:
	mkdir -p bin/

cli: src/cli.c src/cli.h src/utils.h
	$(CC) src/cli.c -c -o bin/cli.o $(CFLAGS)

sniffer: src/sniffer.c src/sniffer.h src/utils.h
	$(CC) src/sniffer.c -c -o bin/sniffer.o $(CFLAGS)

synflood: src/synflood.c src/synflood.h src/cli.h src/sniffer.h src/utils.h
	$(CC) src/synflood.c -c -o bin/synflood.o $(CFLAGS)

utils: src/utils.c src/utils.h
	$(CC) src/utils.c -c -o bin/utils.o $(CFLAGS)

clean:
	rm bin/synflood

