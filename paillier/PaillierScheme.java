package uk.ac.ncl.undergraduate.modules.csc3621.paillier;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * This class implements the algorithms in the Paillier scheme.
 *
 * @author Changyu Dong
 */

public class PaillierScheme {

    private static final int POWER_OF_TWO = 2;

    /**
     * The key generation algorithm.
     *
     * @param n determines the bit length of prime numbers p and q, i.e |p| = |q| = n.
     * @return a valid public private key pair in Paillier scheme.
     */
    public static KeyPair Gen(int n) {

        // Generate two random prime number p and q, both are n-bit long.
        // Ensure p and q are not equal. If they are, generate different q.
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(n, random);
        BigInteger q;

        do {
            q = BigInteger.probablePrime(n, random);
        } while (p.equals(q));

        // Compute N = p · q, N2 = N · N, and φ(N) = (p − 1)(q − 1)
        BigInteger N = p.multiply(q);
        BigInteger N2 = N.pow(POWER_OF_TWO);
        BigInteger phiN = (p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE)));

        // Output a key pair (pk, sk) with pk = (N, N2) and sk = (N, N2, φ(N))
        PublicKey pk = new PublicKey(N, N2);
        PrivateKey sk = new PrivateKey(N, N2, phiN);
        return new KeyPair(pk, sk);
    }

    /**
     * The encryption algorithm
     *
     * @param pk the public key
     * @param m  the plaintext to be encrypted
     * @return the ciphertext of m
     */

    public static BigInteger Enc(PublicKey pk, BigInteger m) {

        BigInteger coprimeNumber;
        BigInteger r;

        SecureRandom random = new SecureRandom();
        int numberOfBitsN = pk.getN().bitLength();

        // find random r smaller than N and coprime with N, which is not 0
        // generate r with same bit length as N, this will ensure no number with bit length > N's is generated
        // if r > N or not coprime, generate another r
        do {
            r = new BigInteger(numberOfBitsN, random);
            coprimeNumber = pk.getN().gcd(r);
        } while (r.compareTo(BigInteger.ZERO) == 0 && !(r.compareTo(pk.getN()) < 0 && coprimeNumber.equals(BigInteger.ONE)));

        //ciphertext = (1 + N)^m · r^N mod N^2
        return (((BigInteger.ONE.add(pk.getN())).pow(m.intValue()))
                .multiply(r.modPow(pk.getN(), pk.getNSqr())))
                .mod(pk.getNSqr());
    }

    /**
     * The decryption algorithm
     *
     * @param sk the private key
     * @param c  the ciphertext to be decrypted
     * @return the plaintext decrypted from c
     */
    public static BigInteger Dec(PrivateKey sk, BigInteger c) {
        /* Compute:
         * a = c^(φ(N)) mod N^2
         * b = (a − 1)/N, (step is performed without mod)
         * m = b · φ(N)^−1 mod N
         */

        BigInteger a = c.modPow(sk.getPhiN(), sk.getNSqr());
        BigInteger b = (a.subtract(BigInteger.ONE)).divide(sk.getN());
        BigInteger m = (b.multiply(sk.getPhiN().modInverse(sk.getN()))).mod(sk.getN());
        return m;
    }

    /**
     * The homomorphic addition algorithm
     *
     * @param pk the public key
     * @param c1 the first ciphertext
     * @param c2 the second ciphertext
     * @return the ciphertext contains the addition result
     */
    public static BigInteger Add(PublicKey pk, BigInteger c1, BigInteger c2) {
        // Compute c3 = c1 · c2 mod N2
        return (c1.multiply(c2)).mod(pk.getNSqr());
    }

    /**
     * The homomorphic multiply with plaintext algorithm
     *
     * @param pk the public key
     * @param s  a plaintext integer
     * @param c  the ciphertext
     * @return the ciphertext contains the multiplication result
     */

    public static BigInteger Multiply(PublicKey pk, BigInteger s, BigInteger c) {
        // Compute c2 = c^s mod N2
        return c.modPow(s, pk.getNSqr());
    }

    /**
     * Main method, tests the correction of the Paillier Scheme, the homomorphic adition, and the homomorphic multiplication
     *
     * @param args
     */
    public static void main(String[] args) {
        KeyPair generation = PaillierScheme.Gen(55);
        PublicKey pk = generation.getPublicKey();
        PrivateKey sk = generation.getPrivateKey();
        BigInteger m = BigInteger.valueOf(5555);

        // Dec(sk, Enc(pk, m)) = m
        System.out.println("Testing correctness:");
        long startTime = System.currentTimeMillis();
        BigInteger encryptionOfMessage = PaillierScheme.Enc(pk, m);
        BigInteger correction = PaillierScheme.Dec(sk, encryptionOfMessage);
        System.out.println("Initial message: " + m);
        System.out.println("Message after encr and decr: " + correction);
        long estimatedTime = System.currentTimeMillis() - startTime;
        System.out.println(estimatedTime);
        if (m.equals(correction)) {
            System.out.println("The correctness property holds for the Paillier encryption scheme!");
        }

        // Dec(sk, Add(pk, Enc(pk, m1), Enc(pk, m2))) = m1 + m2 mod N; for every m1, m2 in ZN
        System.out.println("Testing homomorphic addition:");
        BigInteger m1 = BigInteger.valueOf(45);
        BigInteger m2 = BigInteger.valueOf(67);
        BigInteger addition = (m1.add(m2)).mod(pk.getN());
        BigInteger homomorphicAdd = PaillierScheme.Dec(sk, (PaillierScheme.Add(pk, PaillierScheme.Enc(pk, m1), PaillierScheme.Enc(pk, m2))));
        System.out.println("m1 + m2 mod N: " + addition);
        System.out.println("decryption of addition: " + homomorphicAdd);
        if (addition.equals(homomorphicAdd)) {
            System.out.println("The homomorphic addition holds for the Paillier encryption scheme!");
        }

        // Dec(sk, multiply(pk, m1, Enc(pk, m2))) = m1 · m2 mod N; for every m1, m2 in ZN
        System.out.println("Testing homomorphic multiplication:");
        BigInteger multiplication = (m1.multiply(m2)).mod(pk.getN());
        BigInteger homomorphicMultiplication = PaillierScheme.Dec(sk, PaillierScheme.Multiply(pk, m1, PaillierScheme.Enc(pk, m2)));
        System.out.println("m1 · m2 mod N: " + multiplication);
        System.out.println("decryption of multiplication: " + homomorphicMultiplication);
        if (multiplication.equals(homomorphicMultiplication)) {
            System.out.println("The homomorphic multiply holds for the Paillier encryption scheme!");
        }
    }

}
