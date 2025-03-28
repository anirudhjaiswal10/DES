DES Encryption Project
This repository contains the implementation of the Data Encryption Standard (DES) algorithm along with various test files for evaluating its performance based on different cryptographic properties.

Files and Descriptions
Core Implementation
des.c → Main implementation of the DES encryption algorithm.
des.h → Header file containing function prototypes and definitions.
des.o → Compiled object file for DES.

Cryptographic Property Tests

des_avalanche.c → Evaluates the Avalanche effect in DES.
des_correlation.c → Tests correlation properties of encrypted data.
des_entropy.c → Measures entropy per Feistel round.
des_rounds.c → Analyzes encryption strength based on different round configurations.

Executables
des_avalanche.exe → Executable for avalanche effect testing.
des_correlation.exe → Executable for correlation analysis.
des_entropy.exe → Executable for entropy testing.
des_rounds.exe → Executable for round-based analysis.

Testing and CBC Mode
des_test.c → Test file for DES encryption, includes Initialization Vector (IV) for CBC mode.
des_test.o → Compiled object file for DES testing.
des_test.exe → Executable for DES encryption testing.
