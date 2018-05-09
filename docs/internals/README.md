# CipherSweet Internals

The purpose of this section is to aid the development of cross-platform
libraries that speak the same protocols as CipherSweet and to accelerate
third-party software security assessments.

* [Key Hierarchy](01-key-hierarchy.md) explains how each field gets its
  own encryption key, and how each blind index created on each field
  gets its own distinct key for calculating hashes.
* [Packing](02-packing.md) explains how we pack multi-part messages
  together before passing them into a cryptographic function.
* [Field-Level Encryption](03-encryption.md) explains how each field is
  encrypted in CipherSweet. Knowledge of the Key Hierarchy is a
  pre-requisite to understanding the security consequences of this
  feature.
