CC?=gcc
EXECUTABLE=emdns

all: main

%.o: %.c
	$(CC) -c -g -o $@ $< $(CFLAGS)
	
main: emdns.o main.o masterfile.o
	$(CC) *.c $(CFLAGS) -g -o $(EXECUTABLE)

clean:
	rm *.o $(EXECUTABLE)
