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
* Add `public int elide_restore();` to the trusted section in `Enclave.edl`. 
* Add `void elide_read_file([in, string] const char *secret_file, [out, size=len] uint8_t* buf, size_t len);` to the untrusted section in `Enclave.edl`.
* Add `void elide_server_request([in, string] const char *secret_request, [out, size=len] uint8_t* buf, size_t len);` to the untrusted section in `Enclave.edl`.
* Add a call to `elide_restore` before any other enclave calls.

## Using SGX Elide in a project

Once the library has been added, it is very straightforward to use.  All that needs to be done on the client side is to call `elide_restore` before calling any other enclave functions.

An authentication server must also be set up so that the client can request and retrieve secrets from it, such as the secret code or the decryption key if the code is stored locally but encrypted.

### Encrypting the secret data

If the `-c` flag is passed to `sanitizer.py`, it will encrypt `enclave.secret.dat`.  Currently, every time the project is compiled, a new random encryption key is generated, so there will be new metadata after every compilation in `enclave.secret.meta`.  This new metadata file should be given to the authentication server so that it can provide the correct decryption key to the enclave.

If the secret data is encrypted, the enclave will likely need to retrieve the contents of `enclave.secret.dat` from disk.  Therefore, in such a case this encrypted file should be included in the same directory as the binary.  For now, the file path must be modified in the library if it is necessary to store the data file in a different location than the binary. 

If the secret data is *not* encrypted, then it is important that `enclave.secret.dat` is not kept with the binary.  In such a case, the file should be available only to the authentication server that provides the metadata.

### How SGX Elide works

The process of building and using SGX Elide follows these broad steps:

1. The enclave is compiled into an .so containing the SGX Elide libraries.
2. The sanitizer script is run on the unsigned enclave.so.
  1. All functions not on its whitelist are redacted.  All such functions have their contents replaced with `0`.
  2. The original text section's contents are written to `enclave.secret.dat`.  If the `-c` flag was passed, they are encrypted first.
  3. Metadata is written to `enclave.secret.meta`.  This includes the size of the code and whether it was encrypted.  If it was encrypted, the file also includes the decryption key, initialization vector, and tag/MAC.
  4. The enclave is modified to support self-modification (i.e. the text section is set to be both writable and executable).
3. The enclave is signed by the developer.
4. The developer sets up an authentication server.
5. The developer distributes the binary to customers.  If `enclave.secret.dat` is encrypted, it should be included with the binary.  The `enclave.secret.meta` file is never distributed with the binary.
6. The customer runs the application on an SGX-enabled machine.
7. The enclave is initialized.
8. The application calls `elide_restore`.
  1. Elide initiates a secure connection to the authentication server.
  2. The enclave performs remote attestation to the server to prove it is authentic and can be trusted.
  3. Elide requests the data from the `enclave.secret.meta` file.
    1. If the metadata indicates that `enclave.secret.dat` is encrypted, then the application knows to read it off the local disk.
    2. If the metadata indicates that `enclave.secret.dat` is not encrypted, then the application requests its contents from the server over the secure connection.
  4. Elide retrieves the contents of `enclave.secret.dat`.  If it is encrypted, it uses the decryption key/iv/tag from `enclave.secret.meta` to decrypt it.
  5. Elide copies the original text section's contents over its own code space.  All non-redacted functions have identical bytes copied into them (and therefore suffer no ill effects), and redacted functions are restored.
9. The application calls any ecalls it needs; all previously redacted functions are now unencrypted but still secure, as their code never leaves the enclave.
10. Enclave and program execution can continue as normal.
