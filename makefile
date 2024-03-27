LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.o
	gcc -o pcap-test pcap-test.o -lpcap

pcap-test.o: ess_libnet.h pcap-test.c

clean:
	rm -f pcap-test *.o
