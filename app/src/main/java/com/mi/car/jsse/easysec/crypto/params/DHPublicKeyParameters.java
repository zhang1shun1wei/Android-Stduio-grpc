package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.util.Integers;
import java.math.BigInteger;

public class DHPublicKeyParameters extends DHKeyParameters {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private BigInteger y;

    public DHPublicKeyParameters(BigInteger y2, DHParameters params) {
        super(false, params);
        this.y = validate(y2, params);
    }

    private BigInteger validate(BigInteger y2, DHParameters dhParams) {
        if (y2 == null) {
            throw new NullPointerException("y value cannot be null");
        }
        BigInteger p = dhParams.getP();
        if (y2.compareTo(TWO) < 0 || y2.compareTo(p.subtract(TWO)) > 0) {
            throw new IllegalArgumentException("invalid DH public key");
        }
        BigInteger q = dhParams.getQ();
        if (q == null || (!p.testBit(0) || p.bitLength() - 1 != q.bitLength() || !p.shiftRight(1).equals(q) ? ONE.equals(y2.modPow(q, p)) : 1 == legendre(y2, p))) {
            return y2;
        }
        throw new IllegalArgumentException("Y value does not appear to be in correct group");
    }

    public BigInteger getY() {
        return this.y;
    }

    @Override // com.mi.car.jsse.easysec.crypto.params.DHKeyParameters
    public int hashCode() {
        return this.y.hashCode() ^ super.hashCode();
    }

    @Override // com.mi.car.jsse.easysec.crypto.params.DHKeyParameters
    public boolean equals(Object obj) {
        if ((obj instanceof DHPublicKeyParameters) && ((DHPublicKeyParameters) obj).getY().equals(this.y) && super.equals(obj)) {
            return true;
        }
        return false;
    }

    private static int legendre(BigInteger a, BigInteger b) {
        int bitLength = b.bitLength();
        int[] A = Nat.fromBigInteger(bitLength, a);
        int[] B = Nat.fromBigInteger(bitLength, b);
        int r = 0;
        int len = B.length;
        while (true) {
            if (A[0] == 0) {
                Nat.shiftDownWord(len, A, 0);
            } else {
                int shift = Integers.numberOfTrailingZeros(A[0]);
                if (shift > 0) {
                    Nat.shiftDownBits(len, A, shift, 0);
                    int bits = B[0];
                    r ^= ((bits >>> 1) ^ bits) & (shift << 1);
                }
                int cmp = Nat.compare(len, A, B);
                if (cmp == 0) {
                    break;
                }
                if (cmp < 0) {
                    r ^= A[0] & B[0];
                    A = B;
                    B = A;
                }
                while (A[len - 1] == 0) {
                    len--;
                }
                Nat.sub(len, A, B, A);
            }
        }
        if (Nat.isOne(len, B)) {
            return 1 - (r & 2);
        }
        return 0;
    }
}
