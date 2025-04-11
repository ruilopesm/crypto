## EdDSA

### Overview

EdDSA (Edwards-Curve Digital Signature Algorithm) is a modern digital signature scheme based on elliptic curves, specifically the Edwards curves.
EdDSA is widely used in various applications, including secure messaging, software distribution, and blockchain technologies.

During the implementation of said scheme, I have decided to not implement all the arithmetic operations over elliptic curves from scratch, but rather to use a built-in `EllipticCurve` constructor provided by [Sage](https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/constructor.html). The problem is that such constructor only allows to create Weierstrass elliptic curves. Therefore, I had to write a converter from Edwards curves to Weierstrass curves and vice versa.

It is also important to note that all the parameters used on both implemented curves: Ed25519 and Ed448 were gathered from the RFC 8032, which is referenced at the bottom of this document.

### Modules

- `eddsa.py` which contains an entry point to run all the implemented curves;
- `ed25519.py` which contains the implementation of Ed25519;
- `ed448.py` which contains the implementation of Ed448;
- `utils.py` which contains some utility functions to work with bits and bytes.

### Running

It is important to note that I have not only used Python in this implementation, but also [Sage](https://www.sagemath.org/). Sage is a powerful mathematics software system that provides a wide range of mathematical tools and libraries. It is particularly useful for cryptography, as it has built-in support for many algebraic structures, number theory functions and utilities. That said, you need to have it globally installed on your system.

Then, you can run the main module using the following command:

```bash
python eddsa.py
```

The output will show the results of the Ed25519 and Ed448 signature generation and verification processes.

### References

- https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/
- https://datatracker.ietf.org/doc/html/rfc8032
- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
- https://link.springer.com/chapter/10.1007/978-3-540-68164-9_26
