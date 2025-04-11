## ElGamal over Elliptic Curves

### Overview

In this folder, you can find similar as the ones in the `elgamal` folder, but this time they are implemented over elliptic curves.

It is nice to note that I implemented these in a generic way, meaning that you can use any elliptic curve you want, be it a Edwards curve, a Montgomery curve, a Weierstrass curve, etc. You simply need to pass a bunch of parameters to the constructor of the class and be good to go :D

For demonstration purposes, I have instantiated a Ed25519 curve and a p-256 curve.

### Modules

- `ec_elgamal_pke.py` which contains the default implementation of ElGamal cryptosystem over elliptic curves;
- `ec_elgamal_fo.py` which contains the implementation of ElGamal with Fujisaki-Okamoto Transformation over elliptic curves;
- `utils.py` which contains functions for bootstrapping some chosen elliptic curves and utility functions for mapping and unmapping points to and from an elliptic curve, using the Koblitz method.

### Running

It is important to note that I have not only used Python in this implementation, but also [Sage](https://www.sagemath.org/). Sage is a powerful mathematics software system that provides a wide range of mathematical tools and libraries. It is particularly useful for cryptography, as it has built-in support for many algebraic structures, number theory functions and utilities. That said, you need to have it globally installed on your system.

Then, you can run each module separately. For example, to run the ElGamal PKE module, you can use the following command:

```bash
python ec_elgamal_pke.py
```

To run the ElGamal FO module, you can use the following command:

```bash
python ec_elgamal_fo.py
```

To run the ElGamal KEM module, you can use the following command:

```bash
python ec_elgamal_kem.py
```

The produced outputs will show the usage of both the Ed25519 and p-256 curves. You are free to change code in the modules to use other curves.

## References

- https://neuromancer.sk/std/
- https://crypto.stackexchange.com/a/76343

Check both the [elgamal](../../elgamal/) and [eddsa](../../eddsa/) folders for more references.
