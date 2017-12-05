all : clean tcp_block

tcp_block: tcp_block.o
	g++ -o tcp_block tcp_block.o -lpcap
tcp_block.o:
	g++ -c -o tcp_block.o main.cpp 


test : cleantest client server

client: client.o
	g++ -o client client.o
server: server.o
	g++ -o server server.o
client.o:
	g++ -c -o client.o client.cpp
server.o:
	g++ -c -o server.o server.cpp
clean:
	rm -f *.o
	rm -f tcp_block


