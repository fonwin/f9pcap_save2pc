#!/bin/bash

F9DEV=$HOME/devel

# /usr/bin/c++ -std=c++11 -O3 f9pcap4mcast.cpp -o f9pcap4mcast $F9DEV/output/fon9/release/fon9/libfon9_s.a -I$F9DEV/fon9 -lstdc++ -lpthread -ldl
/usr/bin/c++ -I$F9DEV/fon9  -g -Wall -Wextra -Wconversion -Wold-style-cast -Woverloaded-virtual -Wpointer-arith -Wshadow -Wwrite-strings -fexec-charset=UTF-8 -std=c++11 -O3 -DNDEBUG \
             -o f9pcap4mcast f9pcap4mcast.cpp $F9DEV/output/fon9/release/fon9/libfon9_s.a \
             -lpthread -ldl
strip f9pcap4mcast

