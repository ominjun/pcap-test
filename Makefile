#Makefile
all: pcap-test

pcap-test: mypcap.o main.o
	g++ -o pcap-test mypcap.o main.o -lpcap

main.o: mypcap.h main.cpp

mypcap.o: mypcap.h mypcap.cpp

clean:
	rm -f pcap-test
	rm -f *.o

