package org.krypto.logic;

import java.util.ArrayList;
import java.util.List;
import java.security.SecureRandom;
import java.math.BigInteger;

public class ElGamal {

    private BigInteger[] pubKey;  //(p,g,e) gdzie p - losowa wielka liczba pierwsza
    // g - pierwiastek pierwotny p
    // e - g^a mod p
    private BigInteger privKey;   //a - losowy int przy generowaniu kluczy
    private final int keyLength = 512; //długość klucza w bitach, giga duże wiadomości można
    private final SecureRandom random = new SecureRandom();


    private static List<BigInteger> primeFactors(BigInteger n) {
        List<BigInteger> factors = new ArrayList<>();

        while (n.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            factors.add(BigInteger.TWO);
            n = n.divide(BigInteger.TWO);
        }

        BigInteger i = BigInteger.valueOf(3);
        while (i.multiply(i).compareTo(n) <= 0) {
            while (n.mod(i).equals(BigInteger.ZERO)) {
                factors.add(i);
                n = n.divide(i);
            }
            i = i.add(BigInteger.TWO);
        }

        if (n.compareTo(BigInteger.ONE) > 0) {
            factors.add(n);
        }

        return factors;
    }


    private BigInteger findPrimitiveNumber(BigInteger p) {
        BigInteger q = p.subtract(BigInteger.ONE);
        List<BigInteger> factors = primeFactors(q);
        BigInteger primitive = BigInteger.TWO;
        while (primitive.compareTo(p) < 0) {
            boolean isPrimitve = true;
            for (BigInteger factor : factors) {
                if (primitive.modPow(q.divide(factor), p).equals(BigInteger.ONE)) {
                    isPrimitve = false;
                    break;
                }
            }
            if (isPrimitve) {
                return primitive;
            } else {
                primitive = primitive.add(BigInteger.ONE);
            }

        }
        return BigInteger.ZERO;
    }

    public ElGamal() {
        this.generateKeys();
    }


    public void generateKeys() {
        BigInteger p = BigInteger.probablePrime(keyLength, random);
        BigInteger g = findPrimitiveNumber(p);
        while (!g.equals(BigInteger.ZERO)) {
            p.nextProbablePrime();
            g = findPrimitiveNumber(p);
        }
        BigInteger a = new BigInteger(keyLength, random);
        while (a.compareTo(BigInteger.ONE) <= 0) {
            a = new BigInteger(keyLength, random);
        }
        BigInteger e = g.modPow(a, p);
        pubKey = new BigInteger[]{p, g, e};
        privKey = a;
    }

    public List<BigInteger[]> encrypt(List<byte[]> message) {
        List<BigInteger[]> ciphertext = new ArrayList<>();

        for (byte[] block : message) {
            BigInteger b = new BigInteger(keyLength, random);
            while (b.compareTo(BigInteger.ONE) <= 0) {
                b = new BigInteger(keyLength, random);
            }
            BigInteger m = new BigInteger(1, block);
            ciphertext.add(new BigInteger[]{pubKey[1].modPow(b, pubKey[0]), m.multiply(pubKey[2].modPow(b, pubKey[0]))}); //C1 to [0] C2 to [1]
        }
        return ciphertext;
    }

    public List<byte[]> decrypt(List<BigInteger[]> ciphertext) {
        List<byte[]> decryptedmessage = new ArrayList<>();
        for (BigInteger[] block : ciphertext) {
            BigInteger x = block[0].modPow(privKey, pubKey[0]);
            decryptedmessage.add(block[1].multiply(x.modPow(pubKey[0].subtract(BigInteger.TWO), pubKey[0])).toByteArray());
        }
        return decryptedmessage;
    }


}
