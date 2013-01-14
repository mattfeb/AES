***Only use for learning, do not use for actual security***

AES implementation based on the FIPS 197 standard

The Test.java file contains a simple test to encrypt and then immediately decrypt a text file. The secret key used in this encryption/decryption needs to be saved as the first 16 bytes. After the initial 16 bytes are read in, the rest of the file is partitioned into 16 byte chunks to be encrypted and decrypted. Each chunk of bytes are printed after they are encrypted and decrypted so the same text file is printed after the program terminates. 


To run: javac Test.java
        java Test < inputTextFile