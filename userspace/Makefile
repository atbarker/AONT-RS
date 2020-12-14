ALL: main

dependencies:
	gcc -g -O2 -c aont.c -msse4.2 -g
	gcc -g -O2 -c cauchy_rs.c -msse4.2 -g
	gcc -g -c speck.c


main: dependencies
	gcc -g -O2 -c main.c -g
	gcc -g -O2 -o main main.o aont.o cauchy_rs.o speck.o -lkcapi -g

infer:
	make clean; infer-capture -- make; infer-analyze -- make

test: dependencies
	gcc -g -O2 -c main.c
	gcc -g -O2 -o main main.o aont.o cauchy_rs.o speck.o -lkcapi
	./main
clean:
	rm *.o
	rm main

