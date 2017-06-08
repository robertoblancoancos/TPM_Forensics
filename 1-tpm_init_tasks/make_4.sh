#!/bin/sh

sudo gcc 4_unbind_data.c -L /usr/local/lib -ltspi -lcrypto -o 4_unbind_data
