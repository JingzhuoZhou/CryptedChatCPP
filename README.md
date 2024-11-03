# End-to-End Encrypted Chat Implementation

In this repository, I’ve implemented an end-to-end encrypted chat function. The goal was to create a secure messaging system using various cryptographic techniques. Here’s a breakdown of what I’ve done:

## Project Overview

This project focuses on building a chat application that guarantees message confidentiality and integrity through end-to-end encryption. Key cryptographic functions used include AES, HMAC, HKDF, and the Double Ratchet algorithm.

### Key Features

1. **Cryptographic Functions**: Ported essential cryptographic algorithms from my previous projects, including AES-128, AES-CTR-128, and SHA-256.
2. **HMAC Implementation**: Developed a PRF-HMAC-SHA-256 based on SHA-256, achieving an efficiency of 100 Mbps.
3. **AES-GCM**: Implemented AES-GCM-128, ensuring an efficiency of 50 Mbps.
4. **HKDF**: Created an HKDF based on HMAC-SHA256, targeting 100 Mbps efficiency.
5. **Double Ratchet Algorithm**: Completed the `on_receiving_message` function in `doubleratchet.cpp` and the `receive_message` function in `messenger.cpp` to support secure message exchange.

### Testing

I’ve included some test cases to ensure everything works as intended. The code for AES-GCM, HKDF, and HMAC supports inputs up to 8 Mbit. There are automated tests to check efficiency.

### How to Run the Project

You can compile the project using the following commands:

```bash
make all
```

Or compile individual components with:

```bash
make messenger-test
make messenger
make aes-gcm
make hmac
make hkdf
```

The interactive message tester can be run using:

```bash
bin/messenger
```

In this tester, you can specify the message sender (use 'a' for Alice and 'b' for Bob) and observe whether the messages decrypt correctly.

To run automated tests, execute:

```bash
bin/messenger-test
```

You should see output confirming successful message exchanges.

### Additional Commands

To run specific programs, you can use:

```bash
bin/aes-gcm <input-file> <output-file>
bin/hmac <input-file> <output-file>
bin/hkdf <input-file> <output-file>
```

Batch tests can be executed with:

```bash
bash test.sh  # For Linux
bash test-win.sh  # For Windows
```
