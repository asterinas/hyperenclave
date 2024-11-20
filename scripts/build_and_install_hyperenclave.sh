#!/bin/bash

SCRIPT_DIR=$(dirname "$0")
cd $SCRIPT_DIR/..

check_sme()
{
	if lscpu | grep -wq "sme"; then  # Use -w for word matching
		echo "Current platform supports SME"
		return 1
	else
		echo "Current platform does not support SME"
		return 0
	fi
}

if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <CPU_Vendor> (Intel, AMD, or Hygon)"
	exit 1
fi


# Check if the provided argument is one of the allowed values
CPU_VENDOR="$1"
case "$CPU_VENDOR" in
	Intel)
		echo "Now your choose the CPU vendor: Intel"
		make VENDOR=intel SME=off LOG=warn
		make VENDOR=intel SME=off LOG=warn install
		;;
	AMD|Hygon)
		echo "Now your choose the CPU vendor: $CPU_VENDOR"

		check_sme
		result=$?
		if [ $result -eq 1 ]; then
			echo "SME is supported."
			make VENDOR=amd SME=on LOG=warn
			make VENDOR=amd SME=on LOG=warn install
		elif [ $result -eq 0 ]; then
			echo "SME is not supported."
			make VENDOR=amd SME=off LOG=warn
			make VENDOR=amd SME=off LOG=warn install 
		else
			echo "An unexpected error occurred during the SME check."
		fi
		;;
	*)
		echo "Invalid CPU vendor: $CPU_VENDOR. Please specify Intel, AMD, or Hygon."
		exit 1
		;;
esac

