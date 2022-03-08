all:
	gcc logger.c -o logger
	gcc hw2.c -o logger.so -shared -Wl,--no-as-needed -fPIC -ldl

clean:
	rm -f logger
	rm -f logger.so

