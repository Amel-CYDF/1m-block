LDLIBS = -lnetfilter_queue
CC = g++
CPPFLAGS = -std=c++14

all: 1m-block

1m-block: 1m-block.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f 1m-block *.o
