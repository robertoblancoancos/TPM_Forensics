#!/bin/sh

# Launch i2c test with soft-realtime priority
chrt --rr 99 ./i2c_test data_encrypted

