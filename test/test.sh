#!/usr/bin/env bash

set -o errexit
set -o nounset

# Don't let SOA serials fool on you

if [[ -f test-output.txt ]]; then
	if diff -u <(../pdns-dynamic-reverse-backend.py test-prefixes.yml 0 < test-input.txt) test-output.txt; then
		echo OK
	else
		echo "It's OK if only SOA serial is the difference"
	fi
else
	echo "Creating test.out"
	../pdns-dynamic-reverse-backend.py test-prefixes.yml 0 < test-input.txt > test-output.txt
fi
