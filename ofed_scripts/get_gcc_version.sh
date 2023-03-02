#!/bin/bash
#

gcc --version | head -1 | sed 's/([^)]*)//g' | awk '{print $2}' | \
	awk -F. '{printf "%02d%02d%02d\n", $1, $2, $3}'
