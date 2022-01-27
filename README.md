% tpm2-initramfs-tool(1) tpm2-initramfs-tool | General Commands Manual
%
% MAY 2019

# Overview
This tool using the [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) software stack.
Its purpose is to generate/seal/unseal the FDE encrypytion key into the TPM persistent
object using TPM2 ESAPI.

The code include functions, macros and structures based from the following projects:
* tpm2-tss   https://github.com/tpm2-software/tpm2-tss
* tpm2-totp  https://github.com/tpm2-software/tpm2-totp
* tpm2-tools https://github.com/tpm2-software/tpm2-tools

# Name
**tpm2-initramfs-tool**(1) - Tool used in initramfs to seal/unseal FDE key to the TPM.

# Usage
```
$ ./tpm2-initramfs-tool seal -T device:/dev/tpm0

Generate and seal the key to TPM with the default policy on PCR7 in SHA256
bank.

$ ./tpm2-initramfs-tool unseal -T device:/dev/tpm0

Unseal the key to TPM with the default policy on PCR7 in SHA256 bank.

$ ./tpm2-initramfs-tool seal --pcrs 0,2,4,7 --banks SHA1,SHA256 -T device:/dev/tpmrm0

Generate and seal the key to TPM with the policy on PCR0,PCR2,PCR4,PCR7 in
both SHA1 and SHA256 bank.

$ ./tpm2-initramfs-tool unseal --pcrs 0,2,4,7 --banks SHA1,SHA256 -T device:/dev/tpmrm0

Unseal the key to TPM with the policy on PCR0,PCR2,PCR4,PCR7 in both SHA1
and SHA256 bank.

$ ./tpm2-initramfs-tool seal --data "DATA SEALED" -P 0x81000004 -T device:/dev/tpmrm0

Seal the string "DATA SEALED" to the persistent object address 0x81000004 with the default
policy on PCR7 in SHA256 bank.

```

# Seal FDE key to TPM alone with Ubuntu 20.04 (focal) Desktop

To install FDE with Ubuntu Desktop installer, select "Advanced features" -> "Use LVM with the new Ubuntu Installation" and
check "Encrypt the new Ubuntu installation for security"

Then, fill the security key in next page. For example, "goodpassphrase" for a bad passphrase ;)

Once you have the FDE installed, you can install the package from Ubuntu archive
to store your passphrase to TPM.

```
sudo apt install tpm2-initramfs-tool
sudo tpm2-initramfs-tool seal --data "goodpassphrase"
```

edit /etc/crypttab, change "none" to "unseal", append keyscript=/usr/bin/tpm2-initramfs-tool

Add binaries and libraries to initramfs
```
sudo -i
cat > /etc/initramfs-tools/hooks/tpm2-initramfs-tool <<EOF
. /usr/share/initramfs-tools/hook-functions

copy_exec /usr/lib/x86_64-linux-gnu/libtss2-tcti-device.so.0
copy_exec /usr/bin/tpm2-initramfs-tool
EOF
chmod 755 /etc/initramfs-tools/hooks/tpm2-initramfs-tool
update-initramfs -u
exit
```

Reboot the system, you should not need to type the passphrase and it will unlock the LUKS encrpyted disk from TPM directly.

# Build and install instructions
Standard installation using
```
$ ./bootstrap
$ ./configure
$ make
$ sudo make install
```

# Tests and Code Coverage

Install lcov and configure with --enable-code-coverage.
You will need to install TPM 2.0 simulator for integration tests, see
https://github.com/tpm2-software/tpm2-tools/wiki/Getting-Started#installing-the-tpm20-simulator

```
$ ./configure --enable-code-coverage
$ make check-code-coverage
```

# Notice

Everytime you re-seal the new key it will overwrite the old persistent object.
