object = synflood.o m_pcap.o
fragatt:$(object)
	gcc -g -o fragatt $(object)  -lpthread -lpcap
synflood.o:
	gcc -g -c synflood.c
m_pacp.o:
	gcc -g -c m_pcap.c
clean:
	rm -f *.o fragatt
