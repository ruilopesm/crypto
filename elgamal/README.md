## ElGamal

### Overview

ElGamal is a public-key cryptosystem that uses asymmetric key encryption for secure data transmission. It is based on the Diffie-Hellman key exchange and is widely used for secure communications.

It is known that ElGamal is only IND-CPA secure, meaning that it is not secure against chosen-ciphertext attacks (CCA). To achieve such security, ElGamal can be used in conjunction with a Fujisaki-Okamoto Transformation (FOT). Therefore, I have not only implemented the default ElGamal encryption scheme, but also one using the FOT. The latter is a bit more complex, but it is also more secure.

Finally, I took the liberty to implement a KEM (Key Encapsulation Mechanism) version of ElGamal, which can be used to encapsulate a symmetric key. This is useful for hybrid encryption schemes. The script providing such functionality exemplifies the use of it (DEM) by using a simple One-Time Pad (OTP). The OTP is, obviously, only secure under certain conditions, but it is a good example of how to use the KEM.

### Modules

- `elgamal_pke.py` which contains the default implementation of ElGamal cryptosystem;
- `elgamal_fo.py` which contains the implementation of ElGamal with Fujisaki-Okamoto Transformation;
- `elgamal_kem.py` which contains the implementation of ElGamal KEM;
- `utils.py` which contains some typing annotations and utility functions used in the other modules.

### Running

It is important to note that I have not only used Python in this implementation, but also [Sage](https://www.sagemath.org/). Sage is a powerful mathematics software system that provides a wide range of mathematical tools and libraries. It is particularly useful for cryptography, as it has built-in support for many algebraic structures, number theory functions and utilities. That said, you need to have it globally installed on your system.

Then, you can run each module separately. For example, to run the ElGamal PKE module, you can use the following command:

```bash
python elgamal_pke.py
```

To run the ElGamal FO module, you can use the following command:

```bash
python elgamal_fo.py
```

To run the ElGamal KEM module, you can use the following command:

```bash
python elgamal_kem.py
```

All of the scripts are, in my opinion, well documented and their output is self-explanatory and able to point out the main features or weaknesses of each implemented version.

### References

- https://en.wikipedia.org/wiki/ElGamal_encryption
- https://lukas-prokop.at/articles/2020-06-19-fo-transform
- https://neilmadden.blog/2021/01/22/hybrid-encryption-and-the-kem-dem-paradigm/
- https://doc.sagemath.org/html/en/reference/rings_standard/sage/arith/misc.html
