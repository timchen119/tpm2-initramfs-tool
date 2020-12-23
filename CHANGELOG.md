# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
## [0.2.2] - 2020-12-23
### Added
- To compat with Debian Bullseye
  Update gcc10 and library dependency and compat with Debian Bullseye release.

## [0.2.1] - 2019-08-30
### Added
- To compat with debian release convention
  Remove debian/ in git master, built release tarball on github and use quilt instead of native format.

## [0.2.0] - 2019-08-19
### Added
- Large refactor and add tests/code coverage
  Large refactor, add tests and add functionality to seal provided data and persistent object address.

## [0.1.0] - 2019-05-09
### Added
- Initial release of the tool to be used in the initramfs to generate/seal/unseal the key 
  based on PCR policy using ESAPI from the TCG's TPM Software Stack compliant tpm2-tss libraries 
