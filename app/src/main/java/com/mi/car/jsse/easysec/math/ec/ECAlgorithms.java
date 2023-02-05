package com.mi.car.jsse.easysec.math.ec;

import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.endo.ECEndomorphism;
import com.mi.car.jsse.easysec.math.ec.endo.EndoUtil;
import com.mi.car.jsse.easysec.math.ec.endo.GLVEndomorphism;
import com.mi.car.jsse.easysec.math.field.FiniteField;
import com.mi.car.jsse.easysec.math.field.PolynomialExtensionField;
import com.mi.car.jsse.easysec.math.raw.Nat;
import java.math.BigInteger;

public class ECAlgorithms {
    public static boolean isF2mCurve(ECCurve c) {
        return isF2mField(c.getField());
    }

    public static boolean isF2mField(FiniteField field) {
        return field.getDimension() > 1 && field.getCharacteristic().equals(ECConstants.TWO) && (field instanceof PolynomialExtensionField);
    }

    public static boolean isFpCurve(ECCurve c) {
        return isFpField(c.getField());
    }

    public static boolean isFpField(FiniteField field) {
        return field.getDimension() == 1;
    }

    public static ECPoint sumOfMultiplies(ECPoint[] ps, BigInteger[] ks) {
        if (ps == null || ks == null || ps.length != ks.length || ps.length < 1) {
            throw new IllegalArgumentException("point and scalar arrays should be non-null, and of equal, non-zero, length");
        }
        int count = ps.length;
        switch (count) {
            case 1:
                return ps[0].multiply(ks[0]);
            case 2:
                return sumOfTwoMultiplies(ps[0], ks[0], ps[1], ks[1]);
            default:
                ECPoint p = ps[0];
                ECCurve c = p.getCurve();
                ECPoint[] imported = new ECPoint[count];
                imported[0] = p;
                for (int i = 1; i < count; i++) {
                    imported[i] = importPoint(c, ps[i]);
                }
                ECEndomorphism endomorphism = c.getEndomorphism();
                if (endomorphism instanceof GLVEndomorphism) {
                    return implCheckResult(implSumOfMultipliesGLV(imported, ks, (GLVEndomorphism) endomorphism));
                }
                return implCheckResult(implSumOfMultiplies(imported, ks));
        }
    }

    public static ECPoint sumOfTwoMultiplies(ECPoint P, BigInteger a, ECPoint Q, BigInteger b) {
        ECCurve cp = P.getCurve();
        ECPoint Q2 = importPoint(cp, Q);
        if ((cp instanceof ECCurve.AbstractF2m) && ((ECCurve.AbstractF2m) cp).isKoblitz()) {
            return implCheckResult(P.multiply(a).add(Q2.multiply(b)));
        }
        ECEndomorphism endomorphism = cp.getEndomorphism();
        if (!(endomorphism instanceof GLVEndomorphism)) {
            return implCheckResult(implShamirsTrickWNaf(P, a, Q2, b));
        }
        return implCheckResult(implSumOfMultipliesGLV(new ECPoint[]{P, Q2}, new BigInteger[]{a, b}, (GLVEndomorphism) endomorphism));
    }

    public static ECPoint shamirsTrick(ECPoint P, BigInteger k, ECPoint Q, BigInteger l) {
        return implCheckResult(implShamirsTrickJsf(P, k, importPoint(P.getCurve(), Q), l));
    }

    public static ECPoint importPoint(ECCurve c, ECPoint p) {
        if (c.equals(p.getCurve())) {
            return c.importPoint(p);
        }
        throw new IllegalArgumentException("Point must be on the same curve");
    }

    public static void montgomeryTrick(ECFieldElement[] zs, int off, int len) {
        montgomeryTrick(zs, off, len, null);
    }

    public static void montgomeryTrick(ECFieldElement[] zs, int off, int len, ECFieldElement scale) {
        ECFieldElement[] c = new ECFieldElement[len];
        c[0] = zs[off];
        int i = 0;
        while (true) {
            i++;
            if (i >= len) {
                break;
            }
            c[i] = c[i - 1].multiply(zs[off + i]);
        }
        int i2 = i - 1;
        if (scale != null) {
            c[i2] = c[i2].multiply(scale);
        }
        ECFieldElement u = c[i2].invert();
        int i3 = i2;
        while (i3 > 0) {
            int i4 = i3 - 1;
            int j = off + i3;
            ECFieldElement tmp = zs[j];
            zs[j] = c[i4].multiply(u);
            u = u.multiply(tmp);
            i3 = i4;
        }
        zs[off] = u;
    }

    public static ECPoint referenceMultiply(ECPoint p, BigInteger k) {
        BigInteger x = k.abs();
        ECPoint q = p.getCurve().getInfinity();
        int t = x.bitLength();
        if (t > 0) {
            if (x.testBit(0)) {
                q = p;
            }
            for (int i = 1; i < t; i++) {
                p = p.twice();
                if (x.testBit(i)) {
                    q = q.add(p);
                }
            }
        }
        return k.signum() < 0 ? q.negate() : q;
    }

    public static ECPoint validatePoint(ECPoint p) {
        if (p.isValid()) {
            return p;
        }
        throw new IllegalStateException("Invalid point");
    }

    public static ECPoint cleanPoint(ECCurve c, ECPoint p) {
        if (c.equals(p.getCurve())) {
            return c.decodePoint(p.getEncoded(false));
        }
        throw new IllegalArgumentException("Point must be on the same curve");
    }

    static ECPoint implCheckResult(ECPoint p) {
        if (p.isValidPartial()) {
            return p;
        }
        throw new IllegalStateException("Invalid result");
    }

    static ECPoint implShamirsTrickJsf(ECPoint P, BigInteger k, ECPoint Q, BigInteger l) {
        ECCurve curve = P.getCurve();
        ECPoint infinity = curve.getInfinity();
        ECPoint[] points = {Q, P.subtract(Q), P, P.add(Q)};
        curve.normalizeAll(points);
        ECPoint[] table = {points[3].negate(), points[2].negate(), points[1].negate(), points[0].negate(), infinity, points[0], points[1], points[2], points[3]};
        byte[] jsf = WNafUtil.generateJSF(k, l);
        ECPoint R = infinity;
        int i = jsf.length;
        while (true) {
            i--;
            if (i < 0) {
                return R;
            }
            byte b = jsf[i];
            R = R.twicePlus(table[(((b << 24) >> 28) * 3) + 4 + ((b << 28) >> 28)]);
        }
    }

    static ECPoint implShamirsTrickWNaf(ECPoint P, BigInteger k, ECPoint Q, BigInteger l) {
        boolean negK = k.signum() < 0;
        boolean negL = l.signum() < 0;
        BigInteger kAbs = k.abs();
        BigInteger lAbs = l.abs();
        int minWidthP = WNafUtil.getWindowSize(kAbs.bitLength(), 8);
        int minWidthQ = WNafUtil.getWindowSize(lAbs.bitLength(), 8);
        WNafPreCompInfo infoP = WNafUtil.precompute(P, minWidthP, true);
        WNafPreCompInfo infoQ = WNafUtil.precompute(Q, minWidthQ, true);
        int combSize = FixedPointUtil.getCombSize(P.getCurve());
        if (!negK && !negL && k.bitLength() <= combSize && l.bitLength() <= combSize && infoP.isPromoted() && infoQ.isPromoted()) {
            return implShamirsTrickFixedPoint(P, k, Q, l);
        }
        int widthP = Math.min(8, infoP.getWidth());
        int widthQ = Math.min(8, infoQ.getWidth());
        return implShamirsTrickWNaf(negK ? infoP.getPreCompNeg() : infoP.getPreComp(), negK ? infoP.getPreComp() : infoP.getPreCompNeg(), WNafUtil.generateWindowNaf(widthP, kAbs), negL ? infoQ.getPreCompNeg() : infoQ.getPreComp(), negL ? infoQ.getPreComp() : infoQ.getPreCompNeg(), WNafUtil.generateWindowNaf(widthQ, lAbs));
    }

    static ECPoint implShamirsTrickWNaf(ECEndomorphism endomorphism, ECPoint P, BigInteger k, BigInteger l) {
        boolean negK = k.signum() < 0;
        boolean negL = l.signum() < 0;
        BigInteger k2 = k.abs();
        BigInteger l2 = l.abs();
        WNafPreCompInfo infoP = WNafUtil.precompute(P, WNafUtil.getWindowSize(Math.max(k2.bitLength(), l2.bitLength()), 8), true);
        WNafPreCompInfo infoQ = WNafUtil.precomputeWithPointMap(EndoUtil.mapPoint(endomorphism, P), endomorphism.getPointMap(), infoP, true);
        int widthP = Math.min(8, infoP.getWidth());
        int widthQ = Math.min(8, infoQ.getWidth());
        return implShamirsTrickWNaf(negK ? infoP.getPreCompNeg() : infoP.getPreComp(), negK ? infoP.getPreComp() : infoP.getPreCompNeg(), WNafUtil.generateWindowNaf(widthP, k2), negL ? infoQ.getPreCompNeg() : infoQ.getPreComp(), negL ? infoQ.getPreComp() : infoQ.getPreCompNeg(), WNafUtil.generateWindowNaf(widthQ, l2));
    }

    private static ECPoint implShamirsTrickWNaf(ECPoint[] preCompP, ECPoint[] preCompNegP, byte[] wnafP, ECPoint[] preCompQ, ECPoint[] preCompNegQ, byte[] wnafQ) {
        ECPoint[] tableQ;
        ECPoint[] tableP;
        int len = Math.max(wnafP.length, wnafQ.length);
        ECPoint infinity = preCompP[0].getCurve().getInfinity();
        ECPoint R = infinity;
        int zeroes = 0;
        int i = len - 1;
        while (i >= 0) {
            byte b = i < wnafP.length ? wnafP[i] : 0;
            byte b2 = i < wnafQ.length ? wnafQ[i] : 0;
            if ((b | b2) == 0) {
                zeroes++;
            } else {
                ECPoint r = infinity;
                if (b != 0) {
                    int nP = Math.abs((int) b);
                    if (b < 0) {
                        tableP = preCompNegP;
                    } else {
                        tableP = preCompP;
                    }
                    r = r.add(tableP[nP >>> 1]);
                }
                if (b2 != 0) {
                    int nQ = Math.abs((int) b2);
                    if (b2 < 0) {
                        tableQ = preCompNegQ;
                    } else {
                        tableQ = preCompQ;
                    }
                    r = r.add(tableQ[nQ >>> 1]);
                }
                if (zeroes > 0) {
                    R = R.timesPow2(zeroes);
                    zeroes = 0;
                }
                R = R.twicePlus(r);
            }
            i--;
        }
        if (zeroes > 0) {
            return R.timesPow2(zeroes);
        }
        return R;
    }

    static ECPoint implSumOfMultiplies(ECPoint[] ps, BigInteger[] ks) {
        int count = ps.length;
        boolean[] negs = new boolean[count];
        WNafPreCompInfo[] infos = new WNafPreCompInfo[count];
        byte[][] wnafs = new byte[count][];
        for (int i = 0; i < count; i++) {
            BigInteger ki = ks[i];
            negs[i] = ki.signum() < 0;
            BigInteger ki2 = ki.abs();
            WNafPreCompInfo info = WNafUtil.precompute(ps[i], WNafUtil.getWindowSize(ki2.bitLength(), 8), true);
            int width = Math.min(8, info.getWidth());
            infos[i] = info;
            wnafs[i] = WNafUtil.generateWindowNaf(width, ki2);
        }
        return implSumOfMultiplies(negs, infos, wnafs);
    }

    static ECPoint implSumOfMultipliesGLV(ECPoint[] ps, BigInteger[] ks, GLVEndomorphism glvEndomorphism) {
        BigInteger n = ps[0].getCurve().getOrder();
        int len = ps.length;
        BigInteger[] abs = new BigInteger[(len << 1)];
        int j = 0;
        for (int i = 0; i < len; i++) {
            BigInteger[] ab = glvEndomorphism.decomposeScalar(ks[i].mod(n));
            int j2 = j + 1;
            abs[j] = ab[0];
            j = j2 + 1;
            abs[j2] = ab[1];
        }
        if (glvEndomorphism.hasEfficientPointMap()) {
            return implSumOfMultiplies(glvEndomorphism, ps, abs);
        }
        ECPoint[] pqs = new ECPoint[(len << 1)];
        int j3 = 0;
        for (ECPoint p : ps) {
            ECPoint q = EndoUtil.mapPoint(glvEndomorphism, p);
            int j4 = j3 + 1;
            pqs[j3] = p;
            j3 = j4 + 1;
            pqs[j4] = q;
        }
        return implSumOfMultiplies(pqs, abs);
    }

    static ECPoint implSumOfMultiplies(ECEndomorphism endomorphism, ECPoint[] ps, BigInteger[] ks) {
        int halfCount = ps.length;
        int fullCount = halfCount << 1;
        boolean[] negs = new boolean[fullCount];
        WNafPreCompInfo[] infos = new WNafPreCompInfo[fullCount];
        byte[][] wnafs = new byte[fullCount][];
        ECPointMap pointMap = endomorphism.getPointMap();
        for (int i = 0; i < halfCount; i++) {
            int j0 = i << 1;
            int j1 = j0 + 1;
            BigInteger kj0 = ks[j0];
            negs[j0] = kj0.signum() < 0;
            BigInteger kj02 = kj0.abs();
            BigInteger kj1 = ks[j1];
            negs[j1] = kj1.signum() < 0;
            BigInteger kj12 = kj1.abs();
            int minWidth = WNafUtil.getWindowSize(Math.max(kj02.bitLength(), kj12.bitLength()), 8);
            ECPoint P = ps[i];
            WNafPreCompInfo infoP = WNafUtil.precompute(P, minWidth, true);
            WNafPreCompInfo infoQ = WNafUtil.precomputeWithPointMap(EndoUtil.mapPoint(endomorphism, P), pointMap, infoP, true);
            int widthP = Math.min(8, infoP.getWidth());
            int widthQ = Math.min(8, infoQ.getWidth());
            infos[j0] = infoP;
            infos[j1] = infoQ;
            wnafs[j0] = WNafUtil.generateWindowNaf(widthP, kj02);
            wnafs[j1] = WNafUtil.generateWindowNaf(widthQ, kj12);
        }
        return implSumOfMultiplies(negs, infos, wnafs);
    }

    private static ECPoint implSumOfMultiplies(boolean[] negs, WNafPreCompInfo[] infos, byte[][] wnafs) {
        int len = 0;
        int count = wnafs.length;
        for (byte[] bArr : wnafs) {
            len = Math.max(len, bArr.length);
        }
        ECPoint infinity = infos[0].getPreComp()[0].getCurve().getInfinity();
        ECPoint R = infinity;
        int zeroes = 0;
        int i = len - 1;
        while (i >= 0) {
            ECPoint r = infinity;
            for (int j = 0; j < count; j++) {
                byte[] wnaf = wnafs[j];
                byte b = i < wnaf.length ? wnaf[i] : 0;
                if (b != 0) {
                    int n = Math.abs((int) b);
                    WNafPreCompInfo info = infos[j];
                    r = r.add(((b < 0) == negs[j] ? info.getPreComp() : info.getPreCompNeg())[n >>> 1]);
                }
            }
            if (r == infinity) {
                zeroes++;
            } else {
                if (zeroes > 0) {
                    R = R.timesPow2(zeroes);
                    zeroes = 0;
                }
                R = R.twicePlus(r);
            }
            i--;
        }
        if (zeroes > 0) {
            return R.timesPow2(zeroes);
        }
        return R;
    }

    private static ECPoint implShamirsTrickFixedPoint(ECPoint p, BigInteger k, ECPoint q, BigInteger l) {
        ECCurve c = p.getCurve();
        int combSize = FixedPointUtil.getCombSize(c);
        if (k.bitLength() > combSize || l.bitLength() > combSize) {
            throw new IllegalStateException("fixed-point comb doesn't support scalars larger than the curve order");
        }
        FixedPointPreCompInfo infoP = FixedPointUtil.precompute(p);
        FixedPointPreCompInfo infoQ = FixedPointUtil.precompute(q);
        ECLookupTable lookupTableP = infoP.getLookupTable();
        ECLookupTable lookupTableQ = infoQ.getLookupTable();
        int widthP = infoP.getWidth();
        if (widthP != infoQ.getWidth()) {
            FixedPointCombMultiplier m = new FixedPointCombMultiplier();
            return m.multiply(p, k).add(m.multiply(q, l));
        }
        int d = ((combSize + widthP) - 1) / widthP;
        ECPoint R = c.getInfinity();
        int fullComb = d * widthP;
        int[] K = Nat.fromBigInteger(fullComb, k);
        int[] L = Nat.fromBigInteger(fullComb, l);
        int top = fullComb - 1;
        for (int i = 0; i < d; i++) {
            int secretIndexK = 0;
            int secretIndexL = 0;
            for (int j = top - i; j >= 0; j -= d) {
                int secretBitK = K[j >>> 5] >>> (j & 31);
                secretIndexK = ((secretIndexK ^ (secretBitK >>> 1)) << 1) ^ secretBitK;
                int secretBitL = L[j >>> 5] >>> (j & 31);
                secretIndexL = ((secretIndexL ^ (secretBitL >>> 1)) << 1) ^ secretBitL;
            }
            R = R.twicePlus(lookupTableP.lookupVar(secretIndexK).add(lookupTableQ.lookupVar(secretIndexL)));
        }
        return R.add(infoP.getOffset()).add(infoQ.getOffset());
    }
}
