#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only

# Kselftest framework requirement - SKIP code is 4.
ksft_skip=4

[ -e /dev/tpm0 ] || exit $ksft_skip
[ -e /dev/tpmrm0 ] || exit $ksft_skip
read tpm_version < /sys/class/tpm/tpm0/tpm_version_major
[ "$tpm_version" = 2 ] || exit $ksft_skip

python3 -c 'import sys, tpm2_tests
sys.exit(not tpm2_tests.uring_available())' || exit $ksft_skip

python3 -m unittest -v tpm2_tests.UringTest 2>&1
