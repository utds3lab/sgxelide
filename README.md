# SGX Elide

This project redacts the user functions in an enclave, and provides a mechanism for reinstating them at runtime.  The redacted data is provided to be restored via some secure channel or encrypted source, and once in the enclave, the functions that were redacted can be restored for execution.

There are currently two projects: BaseEnclave and SampleEnclave.

## BaseEnclave

This contains the absolute minimal functions for being able to retrieve and restore redacted functions.  It is used to generate the whitelist of functions that are not redacted.

## SampleEnclave

This is an example enclave project with several user functions that are redacted and restored.

## Adding SGX Elide to a project

It should be simple to add the elide library to a project.  The following changes must be made:

* Copy sanitizer.py into the project's main directory
* Add `@python sanitizer.py -c $(Enclave_Name)` in the `$(Signed_Enclave_Name)` target in the makefile
  * Omit the `-c` flag if you do not want `enclave.secret.dat` to be encrypted
* Copy `Elide_t.cpp` into the Enclave directory
* Copy `Elide_u.cpp` into the App directory
* Add `Enclave/Elide_t.cpp` to the `Enclave_Cpp_Files` variable in the makefile
* Add `App/Elide_u.cpp` to the `App_Cpp_Files` variable in the makefile
* Add a call to `elide_restore` before any other enclave calls.

## Using SGX Elide in a project

Once the library has been added, it is very straightforward to use.  All that needs to be done is to call `elide_restore` before calling any other enclave functions.

### Encrypting the secret data

If the `-c` flag is passed to `sanitizer.py`, it will encrypt `enclave.secret.dat`.  Currently, every time the project is compiled, a new random encryption key is generated, so there will be new metadata after every compilation in `enclave.secret.meta`.  This new metadata file should be given to the authentication server so that it can provide the correct decryption key to the enclave.

If the secret data is encrypted, the enclave will likely need to retrieve the contents of `enclave.secret.dat` from disk.  Therefore, in such a case this encrypted file should be included in the same directory as the binary.  The library must be changed to 

If the secret data is *not* encrypted, then it is important that `enclave.secret.dat` is not kept with the binary.  In such a case, the file should be available only to the authentication server that provides the metadata.
