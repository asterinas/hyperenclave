#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC="\e[0m"

check_fsgsbase()
{
	local SCRIPT_DIR=$(cd $(dirname $0); pwd)
	cd $SCRIPT_DIR

	gcc -o check_fsgsbase check_fsgsbase.c
	./check_fsgsbase &> /dev/null
	return_value=$?
	rm check_fsgsbase
	if [ "$return_value" -eq 0 ]; then
		echo -e "$GREEN [Check FSGSBASE]: PASS $NC"
	else
		echo -e "$RED [Check FSGSBASE]: FAILED $NC"
		exit 1
	fi
}

# Check FSGSBASE is enabled on the current platform
check_fsgsbase
