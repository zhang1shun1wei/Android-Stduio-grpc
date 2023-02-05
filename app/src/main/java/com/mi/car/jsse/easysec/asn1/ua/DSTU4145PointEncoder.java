package com.mi.car.jsse.easysec.asn1.ua;

import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import java.math.BigInteger;
import java.util.Random;

public abstract class DSTU4145PointEncoder {
    private static ECFieldElement trace(ECFieldElement fe) {
        ECFieldElement t = fe;
        for (int i = 1; i < fe.getFieldSize(); i++) {
            t = t.square().add(fe);
        }
        return t;
    }

    private static ECFieldElement solveQuadraticEquation(ECCurve curve, ECFieldElement beta) {
        ECFieldElement z;
        if (beta.isZero()) {
            return beta;
        }
        ECFieldElement zeroElement = curve.fromBigInteger(ECConstants.ZERO);
        Random rand = new Random();
        int m = beta.getFieldSize();
        do {
            ECFieldElement t = curve.fromBigInteger(new BigInteger(m, rand));
            z = zeroElement;
            ECFieldElement w = beta;
            for (int i = 1; i <= m - 1; i++) {
                ECFieldElement w2 = w.square();
                z = z.square().add(w2.multiply(t));
                w = w2.add(beta);
            }
            if (!w.isZero()) {
                return null;
            }
        } while (z.square().add(z).isZero());
        return z;
    }

    public static byte[] encodePoint(ECPoint Q) {
        ECPoint Q2 = Q.normalize();
        ECFieldElement x = Q2.getAffineXCoord();
        byte[] bytes = x.getEncoded();
        if (!x.isZero()) {
            if (trace(Q2.getAffineYCoord().divide(x)).isOne()) {
                int length = bytes.length - 1;
                bytes[length] = (byte) (bytes[length] | 1);
            } else {
                int length2 = bytes.length - 1;
                bytes[length2] = (byte) (bytes[length2] & 254);
            }
        }
        return bytes;
    }

    public static ECPoint decodePoint(ECCurve curve, byte[] bytes) {
        ECFieldElement k = curve.fromBigInteger(BigInteger.valueOf((long) (bytes[bytes.length - 1] & 1)));
        ECFieldElement xp = curve.fromBigInteger(new BigInteger(1, bytes));
        if (!trace(xp).equals(curve.getA())) {
            xp = xp.addOne();
        }
        ECFieldElement yp = null;
        if (xp.isZero()) {
            yp = curve.getB().sqrt();
        } else {
            ECFieldElement z = solveQuadraticEquation(curve, xp.square().invert().multiply(curve.getB()).add(curve.getA()).add(xp));
            if (z != null) {
                if (!trace(z).equals(k)) {
                    z = z.addOne();
                }
                yp = xp.multiply(z);
            }
        }
        if (yp != null) {
            return curve.validatePoint(xp.toBigInteger(), yp.toBigInteger());
        }
        throw new IllegalArgumentException("Invalid point compression");
    }
}
