package com.mi.car.jsse.easysec.crypto.agreement.srp;

import com.mi.car.jsse.easysec.crypto.CryptoException;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SRP6Util {
    private static BigInteger ONE = BigInteger.valueOf(1);
    private static BigInteger ZERO = BigInteger.valueOf(0);

    public static BigInteger calculateK(Digest digest, BigInteger N, BigInteger g) {
        return hashPaddedPair(digest, N, N, g);
    }

    public static BigInteger calculateU(Digest digest, BigInteger N, BigInteger A, BigInteger B) {
        return hashPaddedPair(digest, N, A, B);
    }

    public static BigInteger calculateX(Digest digest, BigInteger N, byte[] salt, byte[] identity, byte[] password) {
        byte[] output = new byte[digest.getDigestSize()];
        digest.update(identity, 0, identity.length);
        digest.update((byte) 58);
        digest.update(password, 0, password.length);
        digest.doFinal(output, 0);
        digest.update(salt, 0, salt.length);
        digest.update(output, 0, output.length);
        digest.doFinal(output, 0);
        return new BigInteger(1, output);
    }

    public static BigInteger generatePrivateValue(Digest digest, BigInteger N, BigInteger g, SecureRandom random) {
        return BigIntegers.createRandomInRange(ONE.shiftLeft(Math.min(256, N.bitLength() / 2) - 1), N.subtract(ONE), random);
    }

    public static BigInteger validatePublicValue(BigInteger N, BigInteger val) throws CryptoException {
        BigInteger val2 = val.mod(N);
        if (!val2.equals(ZERO)) {
            return val2;
        }
        throw new CryptoException("Invalid public value: 0");
    }

    public static BigInteger calculateM1(Digest digest, BigInteger N, BigInteger A, BigInteger B, BigInteger S) {
        return hashPaddedTriplet(digest, N, A, B, S);
    }

    public static BigInteger calculateM2(Digest digest, BigInteger N, BigInteger A, BigInteger M1, BigInteger S) {
        return hashPaddedTriplet(digest, N, A, M1, S);
    }

    public static BigInteger calculateKey(Digest digest, BigInteger N, BigInteger S) {
        byte[] _S = getPadded(S, (N.bitLength() + 7) / 8);
        digest.update(_S, 0, _S.length);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return new BigInteger(1, output);
    }

    private static BigInteger hashPaddedTriplet(Digest digest, BigInteger N, BigInteger n1, BigInteger n2, BigInteger n3) {
        int padLength = (N.bitLength() + 7) / 8;
        byte[] n1_bytes = getPadded(n1, padLength);
        byte[] n2_bytes = getPadded(n2, padLength);
        byte[] n3_bytes = getPadded(n3, padLength);
        digest.update(n1_bytes, 0, n1_bytes.length);
        digest.update(n2_bytes, 0, n2_bytes.length);
        digest.update(n3_bytes, 0, n3_bytes.length);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return new BigInteger(1, output);
    }

    private static BigInteger hashPaddedPair(Digest digest, BigInteger N, BigInteger n1, BigInteger n2) {
        int padLength = (N.bitLength() + 7) / 8;
        byte[] n1_bytes = getPadded(n1, padLength);
        byte[] n2_bytes = getPadded(n2, padLength);
        digest.update(n1_bytes, 0, n1_bytes.length);
        digest.update(n2_bytes, 0, n2_bytes.length);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return new BigInteger(1, output);
    }

    private static byte[] getPadded(BigInteger n, int length) {
        byte[] bs = BigIntegers.asUnsignedByteArray(n);
        if (bs.length >= length) {
            return bs;
        }
        byte[] tmp = new byte[length];
        System.arraycopy(bs, 0, tmp, length - bs.length, bs.length);
        return tmp;
    }
}
