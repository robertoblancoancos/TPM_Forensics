#!/bin/sh

sudo gcc 3_bind_data.c -L /usr/local/lib -ltspi -lcrypto -o 3_bind_data
