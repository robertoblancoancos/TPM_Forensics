#!/bin/sh

sudo gcc timing_attack.c -L /usr/local/lib -O0 -ltspi -lcrypto -o timing_attack
