all: main.c packet_reading.c cfg_processing.c
	gcc main.c packet_reading.c cfg_processing.c -lpcap -ldumbnet -o assign4

clean:
	$(RM) assign4
