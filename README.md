> Tested on:
>
> - Ubuntu 20.04 (OpenSSL 1.1.1f)


# openssl-ed25519

Example how to create and verify ED25519 signatures with OpenSSL


## Usage

	git clone https://github.com/hilbix/openssl-ed25519.git
	cd openssl-ed25519
	make
	make test

Then:

- `openssl genpkey -algorithm ed25519 -out private-key.pem` to create a private key
- `openssl pkey -in private-key.pem -pubout -out public-key.pem` to create public key from private key
- `./sig file public-key.pem private-key.pem` to create a signature for file
  - The signature is also verified against `public-key.pem`, so you can be sure this is the right one
  - The signature is written to stdout
- `./sig file public-key.pem private-key.pem >> file` to append the signature to the given file
  - This modifies the file!
  - Be sure to use `>>` and not `>`, else you sign an empty file
- `./sig file public-key.pem` to verify the file again
  - The signature must be appended at the end of the file as shown in previous step
- `./sig file public-key.pem private-key.pem >> file.sig` to create a detached signature
- `cat file file.sig | ./sig - public-key.pem` to verify the file with a detached signature


## Bugs

> TODO: Move this bugs into issues at GH

- The public key is not embedded/embeddable in the file for now
  - If you have many public keys, it is difficult to find the right one, as you must check each one
  - In future this might be solved by a step which allows to add the public-key to the file and still verify the signature.
  - This will be a backward breaking change
  - `./sig file` will verify signature of the file and output the public key for verification
  - `./sig file pubkey.pem` then will verify with the given public key
- Currently the prefix (`MAGIC0`) is hardcoded to `// `
  - This should be adaptive in that it is taken from `MAGIC2`
  - It then is the part between the `MAGIC2` and the preceeding `\n`
  - This is a backward compatible change
- Fails when the private key is given instead of the public key
  - We should be able to derive the PubK from PrivK
- PrivK cannot have a passphrase
- Signature always is Base64 in a special format for now
  - The generated Base64 cannot be (directly) read by OpenSSL again
  - Either change it such that it can be used in a hybrid way
  - Or implement different output formatters
- Allow public and private key to be read from stdin
  - Allow other file descriptors, too
  - So a number then does not denote a file but an FD


## FAQ

WTF why?

- I am in an isolated lab environment
- This environment only has access to trusted or reviewed sources (like Ubuntu 20.04)
- So it has no access to OpenSSL 3.x, Nighlys, DockerHub, and similar
- But I still needed to be able to create ed25519 signatures

Add public key to file, too?

- Not yet implemented

Bugs?  Contrib?

- Please use GitHub
- Eventually I listen

License?

- This Works is placed under the terms of the Copyright Less License,  
  see file COPYRIGHT.CLL.  USE AT OWN RISK, ABSOLUTELY NO WARRANTY.
- Read: Free as free beer, free speech and free baby.
- Note that this license only applies to code written by me.

