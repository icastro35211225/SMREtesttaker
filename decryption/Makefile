##
#  Thomas White
build: decryptexm.o
	gcc decryptexm.o -o decrypt -ggdb -lmd
run: build
	./decryptexm.c
decryptexm.o: decryptexm.c
	gcc -c decryptexm.c -ggdb -lmd
clean:
	rm -f *.o 2>/dev/null
	rm decrypt


# end
