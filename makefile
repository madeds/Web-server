server:server.c
	gcc -g -o server server.c

source:source.c
	gcc -g -o source source.c
	
client:client.c
	gcc -g -o client client.c
	
serverrun:server
	./server
	
sourcerun:source
	./source 127.0.0.54 36354
	
clientrun:client
	./client 127.0.0.54 36354

clean:
	rm -rf server
	rm -rf client
