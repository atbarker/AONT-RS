ALL: main

dependencies:
	gcc -g -O2 -c aont.c -msse4.2 -g
	gcc -g -O2 -c cauchy_rs.c -msse4.2 -g


main: dependencies
	gcc -g -O2 -c main.c -g
	gcc -g -O2 -o main main.o aont.o cauchy_rs.o -lkcapi -g

test: dependencies
	gcc -g -O2 -c main.c
	gcc -g -O2 -o main main.o aont.o cauchy_rs.o -lkcapi
	./main
clean:
	rm *.o
	rm main

