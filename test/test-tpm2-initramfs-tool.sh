#!/bin/sh
#
# Tests for tpm2-initramfs-tool
#
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2019 Canonical Ltd.
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 or 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

set -eufx

./tpm2-initramfs-tool --help
./tpm2-initramfs-tool -h
./tpm2-initramfs-tool 2>&1 | grep "Missing command"
./tpm2-initramfs-tool nothisarg 2>&1 | grep "Unknown command"
./tpm2-initramfs-tool --nothisoption 2>&1 | grep "Unknown option"
./tpm2-initramfs-tool seal nothisarg 2>&1 | grep "Unknown argument provided"
./tpm2-initramfs-tool seal --tcti nothistcti 2>&1 | grep "Could not open TCTI"
./tpm2-initramfs-tool seal --banks SHA999 2>&1 | grep "Error parsing banks"
./tpm2-initramfs-tool seal --pcrs 0,2,4,kk 2>&1 | grep "Error parsing pcrs"

# if no tpm_server (TPM simulator) or tpm2_startup (from tpm2-tools) found, skip the integration tests
command -v tpm_server >/dev/null 2>&1 || exit 77
command -v tpm2_startup >/dev/null 2>&1 || exit 77

tpm_server_port="$(shuf --input-range 1024-65534 --head-count 1)"
echo "Starting simulator on port $tpm_server_port"
tpm_server -port "$tpm_server_port" &
tpm_server_pid="$!"

cleanup() {
  echo "clean up tpm_server"
  kill "$tpm_server_pid"
}
trap cleanup INT TERM EXIT

sleep 1

tpm2_startup --clear -T mssim:host=localhost,port=$tpm_server_port

# seal the "DATA SEALED" string as a persitent object in TPM simulator, using current PCRs 0,2,4,7 with bank SHA1 and SHA256
./tpm2-initramfs-tool seal --pcrs 0,2,4,7 --banks SHA1,SHA256 --data "DATA SEALED" -T mssim:host=localhost,port=$tpm_server_port
# unseal the data from TPM simulator and check if it works
./tpm2-initramfs-tool unseal --pcrs 0,2,4,7 --banks SHA1,SHA256 -T mssim:host=localhost,port=$tpm_server_port | grep "DATA SEALED"
# seal a TPM random string to address 0x81000004 as a persitant object in TPM simulator, with default PCR 7 on bank SHA384
SEAL_DATA=$(./tpm2-initramfs-tool seal -v -P 0x81000004 --banks SHA384 -T mssim:host=localhost,port=$tpm_server_port)
# unseal from TPM and make sure the data sealed is correct
./tpm2-initramfs-tool unseal -P 0x81000004 --banks SHA384 -v -T mssim:host=localhost,port=$tpm_server_port | grep "$SEAL_DATA"
