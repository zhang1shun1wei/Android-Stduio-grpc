package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.srp;

import com.mi.car.jsse.easysec.tls.NamedGroup;
import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

/* access modifiers changed from: package-private */
public class SRP6Util {
    private static BigInteger ONE = BigInteger.valueOf(1);
    private static BigInteger ZERO = BigInteger.valueOf(0);
    private static final byte[] colon = {58};

    SRP6Util() {
    }

    public static BigInteger calculateK(TlsHash digest, BigInteger N, BigInteger g) {
        return hashPaddedPair(digest, N, N, g);
    }

    public static BigInteger calculateU(TlsHash digest, BigInteger N, BigInteger A, BigInteger B) {
        return hashPaddedPair(digest, N, A, B);
    }

    public static BigInteger calculateX(TlsHash digest, BigInteger N, byte[] salt, byte[] identity, byte[] password) {
        digest.update(identity, 0, identity.length);
        digest.update(colon, 0, 1);
        digest.update(password, 0, password.length);
        byte[] output = digest.calculateHash();
        digest.update(salt, 0, salt.length);
        digest.update(output, 0, output.length);
        return new BigInteger(1, digest.calculateHash());
    }

    public static BigInteger generatePrivateValue(BigInteger N, BigInteger g, SecureRandom random) {
        return BigIntegers.createRandomInRange(ONE.shiftLeft(Math.min((int) NamedGroup.ffdhe2048, N.bitLength() / 2) - 1), N.subtract(ONE), random);
    }

    public static BigInteger validatePublicValue(BigInteger N, BigInteger val) throws IllegalArgumentException {
        BigInteger val2 = val.mod(N);
        if (!val2.equals(ZERO)) {
            return val2;
        }
        throw new IllegalArgumentException("Invalid public value: 0");
    }

    public static BigInteger calculateM1(TlsHash digest, BigInteger N, BigInteger A, BigInteger B, BigInteger S) {
        return hashPaddedTriplet(digest, N, A, B, S);
    }

    public static BigInteger calculateM2(TlsHash digest, BigInteger N, BigInteger A, BigInteger M1, BigInteger S) {
        return hashPaddedTriplet(digest, N, A, M1, S);
    }

    public static BigInteger calculateKey(TlsHash digest, BigInteger N, BigInteger S) {
        byte[] _S = getPadded(S, (N.bitLength() + 7) / 8);
        digest.update(_S, 0, _S.length);
        return new BigInteger(1, digest.calculateHash());
    }

    private static BigInteger hashPaddedTriplet(TlsHash digest, BigInteger N, BigInteger n1, BigInteger n2, BigInteger n3) {
        int padLength = (N.bitLength() + 7) / 8;
        byte[] n1_bytes = getPadded(n1, padLength);
        byte[] n2_bytes = getPadded(n2, padLength);
        byte[] n3_bytes = getPadded(n3, padLength);
        digest.update(n1_bytes, 0, n1_bytes.length);
        digest.update(n2_bytes, 0, n2_bytes.length);
        digest.update(n3_bytes, 0, n3_bytes.length);
        return new BigInteger(1, digest.calculateHash());
    }

    private static BigInteger hashPaddedPair(TlsHash digest, BigInteger N, BigInteger n1, BigInteger n2) {
        int padLength = (N.bitLength() + 7) / 8;
        byte[] n1_bytes = getPadded(n1, padLength);
        byte[] n2_bytes = getPadded(n2, padLength);
        digest.update(n1_bytes, 0, n1_bytes.length);
        digest.update(n2_bytes, 0, n2_bytes.length);
        return new BigInteger(1, digest.calculateHash());
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
