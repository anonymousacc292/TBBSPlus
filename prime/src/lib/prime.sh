#!/bin/bash

rm librust_genprime.a rust_genprime.o
g++ -g -O2 -pthread -march=native -c rust_genprime.cpp -o rust_genprime.o -lgmp
ar rcs librust_genprime.a rust_genprime.o
