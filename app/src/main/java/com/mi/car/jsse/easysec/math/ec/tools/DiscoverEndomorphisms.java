package com.mi.car.jsse.easysec.math.ec.tools;

import com.mi.car.jsse.easysec.asn1.x9.ECNamedCurveTable;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.crypto.ec.CustomNamedCurves;
import com.mi.car.jsse.easysec.math.ec.ECAlgorithms;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.SortedSet;
import java.util.TreeSet;

public class DiscoverEndomorphisms {
    private static final int radix = 16;

    public static void main(String[] args) {
        if (args.length > 0) {
            for (String str : args) {
                discoverEndomorphisms(str);
            }
            return;
        }
        SortedSet<String> curveNames = new TreeSet(enumToList(ECNamedCurveTable.getNames()));
        curveNames.addAll(enumToList(CustomNamedCurves.getNames()));
        for (String str2 : curveNames) {
            discoverEndomorphisms(str2);
        }
    }

    public static void discoverEndomorphisms(X9ECParameters x9) {
        if (x9 == null) {
            throw new NullPointerException("x9");
        }
        discoverEndomorphisms(x9, "<UNKNOWN>");
    }

    private static void discoverEndomorphisms(String curveName) {
        X9ECParameters x9 = CustomNamedCurves.getByName(curveName);
        if (x9 == null && (x9 = ECNamedCurveTable.getByName(curveName)) == null) {
            System.err.println("Unknown curve: " + curveName);
        } else {
            discoverEndomorphisms(x9, curveName);
        }
    }

    private static void discoverEndomorphisms(X9ECParameters x9, String displayName) {
        ECCurve c = x9.getCurve();
        if (ECAlgorithms.isFpCurve(c)) {
            BigInteger characteristic = c.getField().getCharacteristic();
            if (c.getB().isZero() && characteristic.mod(ECConstants.FOUR).equals(ECConstants.ONE)) {
                System.out.println("Curve '" + displayName + "' has a 'GLV Type A' endomorphism with these parameters:");
                printGLVTypeAParameters(x9);
            }
            if (c.getA().isZero() && characteristic.mod(ECConstants.THREE).equals(ECConstants.ONE)) {
                System.out.println("Curve '" + displayName + "' has a 'GLV Type B' endomorphism with these parameters:");
                printGLVTypeBParameters(x9);
            }
        }
    }

    private static void printGLVTypeAParameters(X9ECParameters x9) {
        BigInteger[] lambdas = solveQuadraticEquation(x9.getN(), ECConstants.ONE, ECConstants.ZERO, ECConstants.ONE);
        ECFieldElement[] iValues = findNonTrivialOrder4FieldElements(x9.getCurve());
        printGLVTypeAParameters(x9, lambdas[0], iValues);
        System.out.println("OR");
        printGLVTypeAParameters(x9, lambdas[1], iValues);
    }

    private static void printGLVTypeAParameters(X9ECParameters x9, BigInteger lambda, ECFieldElement[] iValues) {
        ECPoint G = x9.getG().normalize();
        ECPoint mapG = G.multiply(lambda).normalize();
        if (!G.getXCoord().negate().equals(mapG.getXCoord())) {
            throw new IllegalStateException("Derivation of GLV Type A parameters failed unexpectedly");
        }
        ECFieldElement i = iValues[0];
        if (!G.getYCoord().multiply(i).equals(mapG.getYCoord())) {
            i = iValues[1];
            if (!G.getYCoord().multiply(i).equals(mapG.getYCoord())) {
                throw new IllegalStateException("Derivation of GLV Type A parameters failed unexpectedly");
            }
        }
        printProperty("Point map", "lambda * (x, y) = (-x, i * y)");
        printProperty("i", i.toBigInteger().toString(16));
        printProperty("lambda", lambda.toString(16));
        printScalarDecompositionParameters(x9.getN(), lambda);
    }

    private static void printGLVTypeBParameters(X9ECParameters x9) {
        BigInteger[] lambdas = solveQuadraticEquation(x9.getN(), ECConstants.ONE, ECConstants.ONE, ECConstants.ONE);
        ECFieldElement[] betaValues = findNonTrivialOrder3FieldElements(x9.getCurve());
        printGLVTypeBParameters(x9, lambdas[0], betaValues);
        System.out.println("OR");
        printGLVTypeBParameters(x9, lambdas[1], betaValues);
    }

    private static void printGLVTypeBParameters(X9ECParameters x9, BigInteger lambda, ECFieldElement[] betaValues) {
        ECPoint G = x9.getG().normalize();
        ECPoint mapG = G.multiply(lambda).normalize();
        if (!G.getYCoord().equals(mapG.getYCoord())) {
            throw new IllegalStateException("Derivation of GLV Type B parameters failed unexpectedly");
        }
        ECFieldElement beta = betaValues[0];
        if (!G.getXCoord().multiply(beta).equals(mapG.getXCoord())) {
            beta = betaValues[1];
            if (!G.getXCoord().multiply(beta).equals(mapG.getXCoord())) {
                throw new IllegalStateException("Derivation of GLV Type B parameters failed unexpectedly");
            }
        }
        printProperty("Point map", "lambda * (x, y) = (beta * x, y)");
        printProperty("beta", beta.toBigInteger().toString(16));
        printProperty("lambda", lambda.toString(16));
        printScalarDecompositionParameters(x9.getN(), lambda);
    }

    private static void printProperty(String name, Object value) {
        StringBuffer sb = new StringBuffer("  ");
        sb.append(name);
        while (sb.length() < 20) {
            sb.append(' ');
        }
        sb.append(": ");
        sb.append(value.toString());
        System.out.println(sb.toString());
    }

    private static void printScalarDecompositionParameters(BigInteger n, BigInteger lambda) {
        BigInteger[] rt = extEuclidGLV(n, lambda);
        BigInteger[] v1 = {rt[2], rt[3].negate()};
        BigInteger[] v2 = chooseShortest(new BigInteger[]{rt[0], rt[1].negate()}, new BigInteger[]{rt[4], rt[5].negate()});
        if (!isVectorBoundedBySqrt(v2, n) && areRelativelyPrime(v1[0], v1[1])) {
            BigInteger r = v1[0];
            BigInteger t = v1[1];
            BigInteger s = r.add(t.multiply(lambda)).divide(n);
            BigInteger[] vw = extEuclidBezout(new BigInteger[]{s.abs(), t.abs()});
            if (vw != null) {
                BigInteger v = vw[0];
                BigInteger w = vw[1];
                if (s.signum() < 0) {
                    v = v.negate();
                }
                if (t.signum() > 0) {
                    w = w.negate();
                }
                if (!s.multiply(v).subtract(t.multiply(w)).equals(ECConstants.ONE)) {
                    throw new IllegalStateException();
                }
                BigInteger x = w.multiply(n).subtract(v.multiply(lambda));
                BigInteger base1 = v.negate();
                BigInteger base2 = x.negate();
                BigInteger sqrtN = isqrt(n.subtract(ECConstants.ONE)).add(ECConstants.ONE);
                BigInteger[] range = intersect(calculateRange(base1, sqrtN, t), calculateRange(base2, sqrtN, r));
                if (range != null) {
                    for (BigInteger alpha = range[0]; alpha.compareTo(range[1]) <= 0; alpha = alpha.add(ECConstants.ONE)) {
                        BigInteger[] candidate = {x.add(alpha.multiply(r)), v.add(alpha.multiply(t))};
                        if (isShorter(candidate, v2)) {
                            v2 = candidate;
                        }
                    }
                }
            }
        }
        BigInteger d = v1[0].multiply(v2[1]).subtract(v1[1].multiply(v2[0]));
        int bits = (n.bitLength() + 16) - (n.bitLength() & 7);
        BigInteger g1 = roundQuotient(v2[1].shiftLeft(bits), d);
        BigInteger g2 = roundQuotient(v1[1].shiftLeft(bits), d).negate();
        printProperty("v1", "{ " + v1[0].toString(16) + ", " + v1[1].toString(16) + " }");
        printProperty("v2", "{ " + v2[0].toString(16) + ", " + v2[1].toString(16) + " }");
        printProperty("d", d.toString(16));
        printProperty("(OPT) g1", g1.toString(16));
        printProperty("(OPT) g2", g2.toString(16));
        printProperty("(OPT) bits", Integer.toString(bits));
    }

    private static boolean areRelativelyPrime(BigInteger a, BigInteger b) {
        return a.gcd(b).equals(ECConstants.ONE);
    }

    private static BigInteger[] calculateRange(BigInteger mid, BigInteger off, BigInteger div) {
        return order(mid.subtract(off).divide(div), mid.add(off).divide(div));
    }

    private static ArrayList enumToList(Enumeration en) {
        ArrayList rv = new ArrayList();
        while (en.hasMoreElements()) {
            rv.add(en.nextElement());
        }
        return rv;
    }

    private static BigInteger[] extEuclidBezout(BigInteger[] ab) {
        boolean swap = ab[0].compareTo(ab[1]) < 0;
        if (swap) {
            swap(ab);
        }
        BigInteger r0 = ab[0];
        BigInteger r1 = ab[1];
        BigInteger s0 = ECConstants.ONE;
        BigInteger s1 = ECConstants.ZERO;
        BigInteger t0 = ECConstants.ZERO;
        BigInteger t1 = ECConstants.ONE;
        while (r1.compareTo(ECConstants.ONE) > 0) {
            BigInteger[] qr = r0.divideAndRemainder(r1);
            BigInteger q = qr[0];
            BigInteger r2 = qr[1];
            BigInteger s2 = s0.subtract(q.multiply(s1));
            BigInteger t2 = t0.subtract(q.multiply(t1));
            r0 = r1;
            r1 = r2;
            s0 = s1;
            s1 = s2;
            t0 = t1;
            t1 = t2;
        }
        if (r1.signum() <= 0) {
            return null;
        }
        BigInteger[] st = {s1, t1};
        if (!swap) {
            return st;
        }
        swap(st);
        return st;
    }

    private static BigInteger[] extEuclidGLV(BigInteger n, BigInteger lambda) {
        BigInteger r0 = n;
        BigInteger r1 = lambda;
        BigInteger t0 = ECConstants.ZERO;
        BigInteger t1 = ECConstants.ONE;
        while (true) {
            BigInteger[] qr = r0.divideAndRemainder(r1);
            BigInteger q = qr[0];
            BigInteger r2 = qr[1];
            BigInteger t2 = t0.subtract(q.multiply(t1));
            if (isLessThanSqrt(r1, n)) {
                return new BigInteger[]{r0, t0, r1, t1, r2, t2};
            }
            r0 = r1;
            r1 = r2;
            t0 = t1;
            t1 = t2;
        }
    }

    private static BigInteger[] chooseShortest(BigInteger[] u, BigInteger[] v) {
        return isShorter(u, v) ? u : v;
    }

    private static BigInteger[] intersect(BigInteger[] ab, BigInteger[] cd) {
        BigInteger min = ab[0].max(cd[0]);
        BigInteger max = ab[1].min(cd[1]);
        if (min.compareTo(max) > 0) {
            return null;
        }
        return new BigInteger[]{min, max};
    }

    private static boolean isLessThanSqrt(BigInteger a, BigInteger b) {
        BigInteger a2 = a.abs();
        BigInteger b2 = b.abs();
        int target = b2.bitLength();
        int maxBits = a2.bitLength() * 2;
        return maxBits + -1 <= target && (maxBits < target || a2.multiply(a2).compareTo(b2) < 0);
    }

    private static boolean isShorter(BigInteger[] u, BigInteger[] v) {
        boolean c1;
        boolean c12 = true;
        BigInteger u1 = u[0].abs();
        BigInteger u2 = u[1].abs();
        BigInteger v1 = v[0].abs();
        BigInteger v2 = v[1].abs();
        if (u1.compareTo(v1) < 0) {
            c1 = true;
        } else {
            c1 = false;
        }
        if (c1 == (u2.compareTo(v2) < 0)) {
            return c1;
        }
        if (u1.multiply(u1).add(u2.multiply(u2)).compareTo(v1.multiply(v1).add(v2.multiply(v2))) >= 0) {
            c12 = false;
        }
        return c12;
    }

    private static boolean isVectorBoundedBySqrt(BigInteger[] v, BigInteger n) {
        return isLessThanSqrt(v[0].abs().max(v[1].abs()), n);
    }

    private static BigInteger[] order(BigInteger a, BigInteger b) {
        if (a.compareTo(b) <= 0) {
            return new BigInteger[]{a, b};
        }
        return new BigInteger[]{b, a};
    }

    private static BigInteger roundQuotient(BigInteger x, BigInteger y) {
        boolean negative = x.signum() != y.signum();
        BigInteger x2 = x.abs();
        BigInteger y2 = y.abs();
        BigInteger result = x2.add(y2.shiftRight(1)).divide(y2);
        return negative ? result.negate() : result;
    }

    private static BigInteger[] solveQuadraticEquation(BigInteger n, BigInteger a, BigInteger b, BigInteger c) {
        BigInteger root = modSqrt(b.multiply(b).subtract(a.multiply(c).shiftLeft(2)).mod(n), n);
        if (root == null) {
            throw new IllegalStateException("Solving quadratic equation failed unexpectedly");
        }
        BigInteger invDenom = a.shiftLeft(1).modInverse(n);
        return new BigInteger[]{root.subtract(b).multiply(invDenom).mod(n), root.negate().subtract(b).multiply(invDenom).mod(n)};
    }

    private static ECFieldElement[] findNonTrivialOrder3FieldElements(ECCurve c) {
        BigInteger b;
        BigInteger q = c.getField().getCharacteristic();
        BigInteger e = q.divide(ECConstants.THREE);
        SecureRandom random = new SecureRandom();
        do {
            b = BigIntegers.createRandomInRange(ECConstants.TWO, q.subtract(ECConstants.TWO), random).modPow(e, q);
        } while (b.equals(ECConstants.ONE));
        ECFieldElement beta = c.fromBigInteger(b);
        return new ECFieldElement[]{beta, beta.square()};
    }

    private static ECFieldElement[] findNonTrivialOrder4FieldElements(ECCurve c) {
        ECFieldElement i = c.fromBigInteger(ECConstants.ONE).negate().sqrt();
        if (i == null) {
            throw new IllegalStateException("Calculation of non-trivial order-4  field elements failed unexpectedly");
        }
        return new ECFieldElement[]{i, i.negate()};
    }

    private static BigInteger isqrt(BigInteger x) {
        BigInteger g0 = x.shiftRight(x.bitLength() / 2);
        while (true) {
            BigInteger g1 = g0.add(x.divide(g0)).shiftRight(1);
            if (g1.equals(g0)) {
                return g1;
            }
            g0 = g1;
        }
    }

    private static void swap(BigInteger[] ab) {
        BigInteger tmp = ab[0];
        ab[0] = ab[1];
        ab[1] = tmp;
    }

    private static BigInteger modSqrt(BigInteger x, BigInteger p) {
        if (!p.testBit(0)) {
            throw new IllegalStateException();
        }
        BigInteger pSub1Halved = p.subtract(ECConstants.ONE).shiftRight(1);
        BigInteger q = pSub1Halved;
        if (!x.modPow(q, p).equals(ECConstants.ONE)) {
            return null;
        }
        while (!q.testBit(0)) {
            q = q.shiftRight(1);
            if (!x.modPow(q, p).equals(ECConstants.ONE)) {
                return modSqrtComplex(x, q, p, pSub1Halved);
            }
        }
        return x.modPow(q.add(ECConstants.ONE).shiftRight(1), p);
    }

    private static BigInteger modSqrtComplex(BigInteger x, BigInteger q, BigInteger p, BigInteger pSub1Halved) {
        BigInteger a = firstNonResidue(p, pSub1Halved);
        BigInteger t = pSub1Halved;
        while (!q.testBit(0)) {
            q = q.shiftRight(1);
            t = t.shiftRight(1);
            if (!x.modPow(q, p).equals(a.modPow(t, p))) {
                t = t.add(t);
            }
        }
        return x.modInverse(p).modPow(q.subtract(ECConstants.ONE).shiftRight(1), p).multiply(a.modPow(t.shiftRight(1), p)).mod(p);
    }

    private static BigInteger firstNonResidue(BigInteger p, BigInteger pSub1Halved) {
        for (int a = 2; a < 1000; a++) {
            BigInteger A = BigInteger.valueOf((long) a);
            if (!A.modPow(pSub1Halved, p).equals(ECConstants.ONE)) {
                return A;
            }
        }
        throw new IllegalStateException();
    }
}
