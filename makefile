all:netstat.c
	gcc netstat.c -o net
clean:
	rm -f net
