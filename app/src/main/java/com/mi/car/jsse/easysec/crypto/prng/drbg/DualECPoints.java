package com.mi.car.jsse.easysec.crypto.prng.drbg;

import com.mi.car.jsse.easysec.math.ec.ECPoint;

public class DualECPoints {
    private final int cofactor;
    private final ECPoint p;
    private final ECPoint q;
    private final int securityStrength;

    public DualECPoints(int securityStrength2, ECPoint p2, ECPoint q2, int cofactor2) {
        if (!p2.getCurve().equals(q2.getCurve())) {
            throw new IllegalArgumentException("points need to be on the same curve");
        }
        this.securityStrength = securityStrength2;
        this.p = p2;
        this.q = q2;
        this.cofactor = cofactor2;
    }

    public int getSeedLen() {
        return this.p.getCurve().getFieldSize();
    }

    public int getMaxOutlen() {
        return ((this.p.getCurve().getFieldSize() - (log2(this.cofactor) + 13)) / 8) * 8;
    }

    public ECPoint getP() {
        return this.p;
    }

    public ECPoint getQ() {
        return this.q;
    }

    public int getSecurityStrength() {
        return this.securityStrength;
    }

    public int getCofactor() {
        return this.cofactor;
    }

    private static int log2(int value) {
        int log = 0;
        while (true) {
            value >>= 1;
            if (value == 0) {
                return log;
            }
            log++;
        }
    }
}
