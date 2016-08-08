# SGX Elide

This project redacts the user functions in an enclave, and provides a mechanism for reinstating them at runtime.  The redacted data is provided to be restored via some secure channel or encrypted source, and once in the enclave, the functions that were redacted can be restored for execution.

There are currently two projects: BaseEnclave and SampleEnclave.

## BaseEnclave

This contains the absolute minimal functions for being able to retrieve and restore redacted functions.  It is used to generate the whitelist of functions that are not redacted.

## SampleEnclave

This is an example enclave project with several user functions that are redacted and restored.
