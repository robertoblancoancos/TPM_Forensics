#! /bin/bash

echo "GENERATING RANDOM INPUT DATA..."
dd if=/dev/urandom of=data bs=32 count=1
