#!/bin/sh

sudo gcc 1_new_encryption_key.c -L /usr/local/lib -ltspi -lcrypto -o 1_new_encryption_key
