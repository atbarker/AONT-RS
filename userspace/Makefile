ALL: main

dependencies:
	gcc -g -O2 -c aont.c -msse4.2
	gcc -g -O2 -c cauchy_rs.c -msse4.2


main: dependencies
	gcc -g -O2 -c main.c
	gcc -g -O2 -o main main.o aont.o cauchy_rs.o -lkcapi

test: dependencies
	gcc -g -O2 -c city-test.c
	gcc -g -O2 -o city-test city-test.o city.o
	./city-test
clean:
	rm *.o
	rm main
	rm city-test

