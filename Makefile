
CC=gcc

REM=
FLAGS= -Wall -g -O0 -D_GNU_SOURCE  -std=c99
PACK= `pkg-config --cflags gtk+-3.0`
PACKL= `pkg-config --libs gtk+-3.0` 
LIB= -lm


all:
		$(CC) $(FLAGS) $(PACK) PNWl2ktelnet.c Autre.c  md5.c lzhuf_1.c -o PNWl2ktelnet  $(PACKL)  $(LIB) 

clean:
	rm -rf PNWl2ktelnet *.o core
