#!/bin/sh

# Create Endorsement Key
tpm_createek -l debug

# Take ownership of TPM, setting SRK password to well-known 20 zeros
tpm_takeownership -z -l debug
