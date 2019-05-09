# Overview
This tool using the [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) software stack.
Its purpose is to generate/seal/unseal the FDE encrypytion key into the TPM persistent
object using TPM2 ESAPI.

# Build and install instructions
Standard installation using
```
./bootstrap
./configure
make
make install
```

# Usage
```
./tpm2-initramfs-tool seal -T device:/dev/tpm0

Generate and seal the key to TPM with the default policy on PCR7 in SHA256
bank.

./tpm2-initramfs-tool unseal -T device:/dev/tpm0

Unseal the key to TPM with the default policy on PCR7 in SHA256 bank.

./tpm2-initramfs-tool seal --pcrs 0,2,4,7 --banks SHA1,SHA256 -T device:/dev/tpmrm0

Generate and seal the key to TPM with the policy on PCR0,PCR2,PCR4,PCR7 in
both SHA1 and SHA256 bank.

./tpm2-initramfs-tool unseal --pcrs 0,2,4,7 --banks SHA1,SHA256 -T device:/dev/tpmrm0

Unseal the key to TPM with the policy on PCR0,PCR2,PCR4,PCR7 in both SHA1
and SHA256 bank.

```

# Notice

Everytime you re-seal the new key it will overwrite the old persistent object.
