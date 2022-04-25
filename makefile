GXX=gcc
FLAGS=-I./headers
FILES=src/sha256.c src/aes.c src/scrypt.c src/encrypt.c src/utils.c src/filequeue.c

default:
	$(GXX) -g $(FILES) src/main.c -o aes $(FLAGS)
