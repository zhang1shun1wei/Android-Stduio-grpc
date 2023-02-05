//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.math.ec;

import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.math.Primes;
import com.mi.car.jsse.easysec.math.ec.endo.ECEndomorphism;
import com.mi.car.jsse.easysec.math.ec.endo.GLVEndomorphism;
import com.mi.car.jsse.easysec.math.field.FiniteField;
import com.mi.car.jsse.easysec.math.field.FiniteFields;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.util.BigIntegers;
import com.mi.car.jsse.easysec.util.Integers;
import com.mi.car.jsse.easysec.util.Properties;
import com.mi.car.jsse.easysec.util.BigIntegers.Cache;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Random;
import java.util.Set;

public abstract class ECCurve {
    public static final int COORD_AFFINE = 0;
    public static final int COORD_HOMOGENEOUS = 1;
    public static final int COORD_JACOBIAN = 2;
    public static final int COORD_JACOBIAN_CHUDNOVSKY = 3;
    public static final int COORD_JACOBIAN_MODIFIED = 4;
    public static final int COORD_LAMBDA_AFFINE = 5;
    public static final int COORD_LAMBDA_PROJECTIVE = 6;
    public static final int COORD_SKEWED = 7;
    protected FiniteField field;
    protected ECFieldElement a;
    protected ECFieldElement b;
    protected BigInteger order;
    protected BigInteger cofactor;
    protected int coord = 0;
    protected ECEndomorphism endomorphism = null;
    protected ECMultiplier multiplier = null;

    public static int[] getAllCoordinateSystems() {
        return new int[]{0, 1, 2, 3, 4, 5, 6, 7};
    }

    protected ECCurve(FiniteField field) {
        this.field = field;
    }

    public abstract int getFieldSize();

    public abstract ECFieldElement fromBigInteger(BigInteger var1);

    public abstract boolean isValidFieldElement(BigInteger var1);

    public abstract ECFieldElement randomFieldElement(SecureRandom var1);

    public abstract ECFieldElement randomFieldElementMult(SecureRandom var1);

    public synchronized ECCurve.Config configure() {
        return new ECCurve.Config(this.coord, this.endomorphism, this.multiplier);
    }

    public ECPoint validatePoint(BigInteger x, BigInteger y) {
        ECPoint p = this.createPoint(x, y);
        if (!p.isValid()) {
            throw new IllegalArgumentException("Invalid point coordinates");
        } else {
            return p;
        }
    }

    public ECPoint createPoint(BigInteger x, BigInteger y) {
        return this.createRawPoint(this.fromBigInteger(x), this.fromBigInteger(y));
    }

    protected abstract ECCurve cloneCurve();

    protected abstract ECPoint createRawPoint(ECFieldElement var1, ECFieldElement var2);

    protected abstract ECPoint createRawPoint(ECFieldElement var1, ECFieldElement var2, ECFieldElement[] var3);

    protected ECMultiplier createDefaultMultiplier() {
        return (ECMultiplier)(this.endomorphism instanceof GLVEndomorphism ? new GLVMultiplier(this, (GLVEndomorphism)this.endomorphism) : new WNafL2RMultiplier());
    }

    public boolean supportsCoordinateSystem(int coord) {
        return coord == 0;
    }

    public PreCompInfo getPreCompInfo(ECPoint point, String name) {
        this.checkPoint(point);
        Hashtable table;
        synchronized(point) {
            table = point.preCompTable;
        }

        if (null == table) {
            return null;
        } else {
            synchronized(table) {
                return (PreCompInfo)table.get(name);
            }
        }
    }

    public PreCompInfo precompute(ECPoint point, String name, PreCompCallback callback) {
        this.checkPoint(point);
        Hashtable table;
        synchronized(point) {
            table = point.preCompTable;
            if (null == table) {
                point.preCompTable = table = new Hashtable(4);
            }
        }

        synchronized(table) {
            PreCompInfo existing = (PreCompInfo)table.get(name);
            PreCompInfo result = callback.precompute(existing);
            if (result != existing) {
                table.put(name, result);
            }

            return result;
        }
    }

    public ECPoint importPoint(ECPoint p) {
        if (this == p.getCurve()) {
            return p;
        } else if (p.isInfinity()) {
            return this.getInfinity();
        } else {
            p = p.normalize();
            return this.createPoint(p.getXCoord().toBigInteger(), p.getYCoord().toBigInteger());
        }
    }

    public void normalizeAll(ECPoint[] points) {
        this.normalizeAll(points, 0, points.length, (ECFieldElement)null);
    }

    public void normalizeAll(ECPoint[] points, int off, int len, ECFieldElement iso) {
        this.checkPoints(points, off, len);
        switch(this.getCoordinateSystem()) {
            case 0:
            case 5:
                if (iso != null) {
                    throw new IllegalArgumentException("'iso' not valid for affine coordinates");
                }

                return;
            default:
                ECFieldElement[] zs = new ECFieldElement[len];
                int[] indices = new int[len];
                int count = 0;
                int j = 0;

                for(; j < len; ++j) {
                    ECPoint p = points[off + j];
                    if (null != p && (iso != null || !p.isNormalized())) {
                        zs[count] = p.getZCoord(0);
                        indices[count++] = off + j;
                    }
                }

                if (count != 0) {
                    ECAlgorithms.montgomeryTrick(zs, 0, count, iso);

                    for(j = 0; j < count; ++j) {
                        int index = indices[j];
                        points[index] = points[index].normalize(zs[j]);
                    }

                }
        }
    }

    public abstract ECPoint getInfinity();

    public FiniteField getField() {
        return this.field;
    }

    public ECFieldElement getA() {
        return this.a;
    }

    public ECFieldElement getB() {
        return this.b;
    }

    public BigInteger getOrder() {
        return this.order;
    }

    public BigInteger getCofactor() {
        return this.cofactor;
    }

    public int getCoordinateSystem() {
        return this.coord;
    }

    protected abstract ECPoint decompressPoint(int var1, BigInteger var2);

    public ECEndomorphism getEndomorphism() {
        return this.endomorphism;
    }

    public ECMultiplier getMultiplier() {
        if (this.multiplier == null) {
            this.multiplier = this.createDefaultMultiplier();
        }

        return this.multiplier;
    }

    public ECPoint decodePoint(byte[] encoded) {
        ECPoint p = null;
        int expectedLength = (this.getFieldSize() + 7) / 8;
        byte type = encoded[0];
        BigInteger X;
        BigInteger Y;
        switch(type) {
            case 0:
                if (encoded.length != 1) {
                    throw new IllegalArgumentException("Incorrect length for infinity encoding");
                }

                p = this.getInfinity();
                break;
            case 1:
            case 5:
            default:
                throw new IllegalArgumentException("Invalid point encoding 0x" + Integer.toString(type, 16));
            case 2:
            case 3:
                if (encoded.length != expectedLength + 1) {
                    throw new IllegalArgumentException("Incorrect length for compressed encoding");
                }

                int yTilde = type & 1;
                Y = BigIntegers.fromUnsignedByteArray(encoded, 1, expectedLength);
                p = this.decompressPoint(yTilde, Y);
                if (!p.implIsValid(true, true)) {
                    throw new IllegalArgumentException("Invalid point");
                }
                break;
            case 4:
                if (encoded.length != 2 * expectedLength + 1) {
                    throw new IllegalArgumentException("Incorrect length for uncompressed encoding");
                }

                X = BigIntegers.fromUnsignedByteArray(encoded, 1, expectedLength);
                Y = BigIntegers.fromUnsignedByteArray(encoded, 1 + expectedLength, expectedLength);
                p = this.validatePoint(X, Y);
                break;
            case 6:
            case 7:
                if (encoded.length != 2 * expectedLength + 1) {
                    throw new IllegalArgumentException("Incorrect length for hybrid encoding");
                }

                X = BigIntegers.fromUnsignedByteArray(encoded, 1, expectedLength);
                Y = BigIntegers.fromUnsignedByteArray(encoded, 1 + expectedLength, expectedLength);
                if (Y.testBit(0) != (type == 7)) {
                    throw new IllegalArgumentException("Inconsistent Y coordinate in hybrid encoding");
                }

                p = this.validatePoint(X, Y);
        }

        if (type != 0 && p.isInfinity()) {
            throw new IllegalArgumentException("Invalid infinity encoding");
        } else {
            return p;
        }
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len) {
        final int FE_BYTES = this.getFieldSize() + 7 >>> 3;
        final byte[] table = new byte[len * FE_BYTES * 2];
        int pos = 0;

        for(int i = 0; i < len; ++i) {
            ECPoint p = points[off + i];
            byte[] px = p.getRawXCoord().toBigInteger().toByteArray();
            byte[] py = p.getRawYCoord().toBigInteger().toByteArray();
            int pxStart = px.length > FE_BYTES ? 1 : 0;
            int pxLen = px.length - pxStart;
            int pyStart = py.length > FE_BYTES ? 1 : 0;
            int pyLen = py.length - pyStart;
            System.arraycopy(px, pxStart, table, pos + FE_BYTES - pxLen, pxLen);
            pos += FE_BYTES;
            System.arraycopy(py, pyStart, table, pos + FE_BYTES - pyLen, pyLen);
            pos += FE_BYTES;
        }

        return new AbstractECLookupTable() {
            public int getSize() {
                return len;
            }

            public ECPoint lookup(int index) {
                byte[] x = new byte[FE_BYTES];
                byte[] y = new byte[FE_BYTES];
                int pos = 0;

                for(int i = 0; i < len; ++i) {
                    int MASK = (i ^ index) - 1 >> 31;

                    for(int j = 0; j < FE_BYTES; ++j) {
                        x[j] = (byte)(x[j] ^ table[pos + j] & MASK);
                        y[j] = (byte)(y[j] ^ table[pos + FE_BYTES + j] & MASK);
                    }

                    pos += FE_BYTES * 2;
                }

                return this.createPoint(x, y);
            }

            public ECPoint lookupVar(int index) {
                byte[] x = new byte[FE_BYTES];
                byte[] y = new byte[FE_BYTES];
                int pos = index * FE_BYTES * 2;

                for(int j = 0; j < FE_BYTES; ++j) {
                    x[j] = table[pos + j];
                    y[j] = table[pos + FE_BYTES + j];
                }

                return this.createPoint(x, y);
            }

            private ECPoint createPoint(byte[] x, byte[] y) {
                return ECCurve.this.createRawPoint(ECCurve.this.fromBigInteger(new BigInteger(1, x)), ECCurve.this.fromBigInteger(new BigInteger(1, y)));
            }
        };
    }

    protected void checkPoint(ECPoint point) {
        if (null == point || this != point.getCurve()) {
            throw new IllegalArgumentException("'point' must be non-null and on this curve");
        }
    }

    protected void checkPoints(ECPoint[] points) {
        this.checkPoints(points, 0, points.length);
    }

    protected void checkPoints(ECPoint[] points, int off, int len) {
        if (points == null) {
            throw new IllegalArgumentException("'points' cannot be null");
        } else if (off >= 0 && len >= 0 && off <= points.length - len) {
            for(int i = 0; i < len; ++i) {
                ECPoint point = points[off + i];
                if (null != point && this != point.getCurve()) {
                    throw new IllegalArgumentException("'points' entries must be null or on this curve");
                }
            }

        } else {
            throw new IllegalArgumentException("invalid range specified for 'points'");
        }
    }

    public boolean equals(ECCurve other) {
        return this == other || null != other && this.getField().equals(other.getField()) && this.getA().toBigInteger().equals(other.getA().toBigInteger()) && this.getB().toBigInteger().equals(other.getB().toBigInteger());
    }

    public boolean equals(Object obj) {
        return this == obj || obj instanceof ECCurve && this.equals((ECCurve)obj);
    }

    public int hashCode() {
        return this.getField().hashCode() ^ Integers.rotateLeft(this.getA().toBigInteger().hashCode(), 8) ^ Integers.rotateLeft(this.getB().toBigInteger().hashCode(), 16);
    }

    private static int getNumberOfIterations(int bits, int certainty) {
        if (bits >= 1536) {
            return certainty <= 100 ? 3 : (certainty <= 128 ? 4 : 4 + (certainty - 128 + 1) / 2);
        } else if (bits >= 1024) {
            return certainty <= 100 ? 4 : (certainty <= 112 ? 5 : 5 + (certainty - 112 + 1) / 2);
        } else if (bits >= 512) {
            return certainty <= 80 ? 5 : (certainty <= 100 ? 7 : 7 + (certainty - 100 + 1) / 2);
        } else {
            return certainty <= 80 ? 40 : 40 + (certainty - 80 + 1) / 2;
        }
    }

    public static class F2m extends ECCurve.AbstractF2m {
        private static final int F2M_DEFAULT_COORDS = 6;
        private int m;
        private int k1;
        private int k2;
        private int k3;
        private com.mi.car.jsse.easysec.math.ec.ECPoint.F2m infinity;

        /** @deprecated */
        public F2m(int m, int k, BigInteger a, BigInteger b) {
            this(m, k, 0, 0, (BigInteger)a, (BigInteger)b, (BigInteger)null, (BigInteger)null);
        }

        public F2m(int m, int k, BigInteger a, BigInteger b, BigInteger order, BigInteger cofactor) {
            this(m, k, 0, 0, (BigInteger)a, (BigInteger)b, order, cofactor);
        }

        /** @deprecated */
        public F2m(int m, int k1, int k2, int k3, BigInteger a, BigInteger b) {
            this(m, k1, k2, k3, (BigInteger)a, (BigInteger)b, (BigInteger)null, (BigInteger)null);
        }

        public F2m(int m, int k1, int k2, int k3, BigInteger a, BigInteger b, BigInteger order, BigInteger cofactor) {
            super(m, k1, k2, k3);
            this.m = m;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;
            this.order = order;
            this.cofactor = cofactor;
            this.infinity = new com.mi.car.jsse.easysec.math.ec.ECPoint.F2m(this, (ECFieldElement)null, (ECFieldElement)null);
            this.a = this.fromBigInteger(a);
            this.b = this.fromBigInteger(b);
            this.coord = 6;
        }

        protected F2m(int m, int k1, int k2, int k3, ECFieldElement a, ECFieldElement b, BigInteger order, BigInteger cofactor) {
            super(m, k1, k2, k3);
            this.m = m;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;
            this.order = order;
            this.cofactor = cofactor;
            this.infinity = new com.mi.car.jsse.easysec.math.ec.ECPoint.F2m(this, (ECFieldElement)null, (ECFieldElement)null);
            this.a = a;
            this.b = b;
            this.coord = 6;
        }

        protected ECCurve cloneCurve() {
            return new ECCurve.F2m(this.m, this.k1, this.k2, this.k3, this.a, this.b, this.order, this.cofactor);
        }

        public boolean supportsCoordinateSystem(int coord) {
            switch(coord) {
                case 0:
                case 1:
                case 6:
                    return true;
                default:
                    return false;
            }
        }

        protected ECMultiplier createDefaultMultiplier() {
            return (ECMultiplier)(this.isKoblitz() ? new WTauNafMultiplier() : super.createDefaultMultiplier());
        }

        public int getFieldSize() {
            return this.m;
        }

        public ECFieldElement fromBigInteger(BigInteger x) {
            return new com.mi.car.jsse.easysec.math.ec.ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, x);
        }

        protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y) {
            return new com.mi.car.jsse.easysec.math.ec.ECPoint.F2m(this, x, y);
        }

        protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
            return new com.mi.car.jsse.easysec.math.ec.ECPoint.F2m(this, x, y, zs);
        }

        public ECPoint getInfinity() {
            return this.infinity;
        }

        public int getM() {
            return this.m;
        }

        public boolean isTrinomial() {
            return this.k2 == 0 && this.k3 == 0;
        }

        public int getK1() {
            return this.k1;
        }

        public int getK2() {
            return this.k2;
        }

        public int getK3() {
            return this.k3;
        }

        public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len) {
            final int FE_LONGS = this.m + 63 >>> 6;
            final int[] ks = this.isTrinomial() ? new int[]{this.k1} : new int[]{this.k1, this.k2, this.k3};
            final long[] table = new long[len * FE_LONGS * 2];
            int pos = 0;

            for(int i = 0; i < len; ++i) {
                ECPoint p = points[off + i];
                ((com.mi.car.jsse.easysec.math.ec.ECFieldElement.F2m)p.getRawXCoord()).x.copyTo(table, pos);
                pos += FE_LONGS;
                ((com.mi.car.jsse.easysec.math.ec.ECFieldElement.F2m)p.getRawYCoord()).x.copyTo(table, pos);
                pos += FE_LONGS;
            }

            return new AbstractECLookupTable() {
                public int getSize() {
                    return len;
                }

                public ECPoint lookup(int index) {
                    long[] x = Nat.create64(FE_LONGS);
                    long[] y = Nat.create64(FE_LONGS);
                    int pos = 0;

                    for(int i = 0; i < len; ++i) {
                        long MASK = (long)((i ^ index) - 1 >> 31);

                        for(int j = 0; j < FE_LONGS; ++j) {
                            x[j] ^= table[pos + j] & MASK;
                            y[j] ^= table[pos + FE_LONGS + j] & MASK;
                        }

                        pos += FE_LONGS * 2;
                    }

                    return this.createPoint(x, y);
                }

                public ECPoint lookupVar(int index) {
                    long[] x = Nat.create64(FE_LONGS);
                    long[] y = Nat.create64(FE_LONGS);
                    int pos = index * FE_LONGS * 2;

                    for(int j = 0; j < FE_LONGS; ++j) {
                        x[j] = table[pos + j];
                        y[j] = table[pos + FE_LONGS + j];
                    }

                    return this.createPoint(x, y);
                }

                private ECPoint createPoint(long[] x, long[] y) {
                    com.mi.car.jsse.easysec.math.ec.ECFieldElement.F2m X = new com.mi.car.jsse.easysec.math.ec.ECFieldElement.F2m(F2m.this.m, ks, new LongArray(x));
                    com.mi.car.jsse.easysec.math.ec.ECFieldElement.F2m Y = new com.mi.car.jsse.easysec.math.ec.ECFieldElement.F2m(F2m.this.m, ks, new LongArray(y));
                    return F2m.this.createRawPoint(X, Y);
                }
            };
        }
    }

    public abstract static class AbstractF2m extends ECCurve {
        private BigInteger[] si = null;

        public static BigInteger inverse(int m, int[] ks, BigInteger x) {
            return (new LongArray(x)).modInverse(m, ks).toBigInteger();
        }

        private static FiniteField buildField(int m, int k1, int k2, int k3) {
            if (k1 == 0) {
                throw new IllegalArgumentException("k1 must be > 0");
            } else if (k2 == 0) {
                if (k3 != 0) {
                    throw new IllegalArgumentException("k3 must be 0 if k2 == 0");
                } else {
                    return FiniteFields.getBinaryExtensionField(new int[]{0, k1, m});
                }
            } else if (k2 <= k1) {
                throw new IllegalArgumentException("k2 must be > k1");
            } else if (k3 <= k2) {
                throw new IllegalArgumentException("k3 must be > k2");
            } else {
                return FiniteFields.getBinaryExtensionField(new int[]{0, k1, k2, k3, m});
            }
        }

        protected AbstractF2m(int m, int k1, int k2, int k3) {
            super(buildField(m, k1, k2, k3));
        }

        public ECPoint createPoint(BigInteger x, BigInteger y) {
            ECFieldElement X = this.fromBigInteger(x);
            ECFieldElement Y = this.fromBigInteger(y);
            int coord = this.getCoordinateSystem();
            switch(coord) {
                case 5:
                case 6:
                    if (X.isZero()) {
                        if (!Y.square().equals(this.getB())) {
                            throw new IllegalArgumentException();
                        }
                    } else {
                        Y = Y.divide(X).add(X);
                    }
                default:
                    return this.createRawPoint(X, Y);
            }
        }

        public boolean isValidFieldElement(BigInteger x) {
            return x != null && x.signum() >= 0 && x.bitLength() <= this.getFieldSize();
        }

        public ECFieldElement randomFieldElement(SecureRandom r) {
            int m = this.getFieldSize();
            return this.fromBigInteger(BigIntegers.createRandomBigInteger(m, r));
        }

        public ECFieldElement randomFieldElementMult(SecureRandom r) {
            int m = this.getFieldSize();
            ECFieldElement fe1 = this.fromBigInteger(implRandomFieldElementMult(r, m));
            ECFieldElement fe2 = this.fromBigInteger(implRandomFieldElementMult(r, m));
            return fe1.multiply(fe2);
        }

        protected ECPoint decompressPoint(int yTilde, BigInteger X1) {
            ECFieldElement x = this.fromBigInteger(X1);
            ECFieldElement y = null;
            if (x.isZero()) {
                y = this.getB().sqrt();
            } else {
                ECFieldElement beta = x.square().invert().multiply(this.getB()).add(this.getA()).add(x);
                ECFieldElement z = this.solveQuadraticEquation(beta);
                if (z != null) {
                    if (z.testBitZero() != (yTilde == 1)) {
                        z = z.addOne();
                    }

                    switch(this.getCoordinateSystem()) {
                        case 5:
                        case 6:
                            y = z.add(x);
                            break;
                        default:
                            y = z.multiply(x);
                    }
                }
            }

            if (y == null) {
                throw new IllegalArgumentException("Invalid point compression");
            } else {
                return this.createRawPoint(x, y);
            }
        }

        protected ECFieldElement solveQuadraticEquation(ECFieldElement beta) {
            com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m betaF2m = (com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m)beta;
            boolean fastTrace = betaF2m.hasFastTrace();
            if (fastTrace && 0 != betaF2m.trace()) {
                return null;
            } else {
                int m = this.getFieldSize();
                ECFieldElement gamma;
                if (0 != (m & 1)) {
                    gamma = betaF2m.halfTrace();
                    return !fastTrace && !gamma.square().add(gamma).add(beta).isZero() ? null : gamma;
                } else if (beta.isZero()) {
                    return beta;
                } else {
                    ECFieldElement zeroElement = this.fromBigInteger(ECConstants.ZERO);
                    Random rand = new Random();

                    ECFieldElement z;
                    do {
                        ECFieldElement t = this.fromBigInteger(new BigInteger(m, rand));
                        z = zeroElement;
                        ECFieldElement w = beta;

                        for(int i = 1; i < m; ++i) {
                            ECFieldElement w2 = w.square();
                            z = z.square().add(w2.multiply(t));
                            w = w2.add(beta);
                        }

                        if (!w.isZero()) {
                            return null;
                        }

                        gamma = z.square().add(z);
                    } while(gamma.isZero());

                    return z;
                }
            }
        }

        synchronized BigInteger[] getSi() {
            if (this.si == null) {
                this.si = Tnaf.getSi(this);
            }

            return this.si;
        }

        public boolean isKoblitz() {
            return this.order != null && this.cofactor != null && this.b.isOne() && (this.a.isZero() || this.a.isOne());
        }

        private static BigInteger implRandomFieldElementMult(SecureRandom r, int m) {
            BigInteger x;
            do {
                x = BigIntegers.createRandomBigInteger(m, r);
            } while(x.signum() <= 0);

            return x;
        }
    }

    public static class Fp extends ECCurve.AbstractFp {
        private static final int FP_DEFAULT_COORDS = 4;
        private static final Set<BigInteger> knownQs = Collections.synchronizedSet(new HashSet());
        private static final Cache validatedQs = new Cache();
        BigInteger q;
        BigInteger r;
        com.mi.car.jsse.easysec.math.ec.ECPoint.Fp infinity;

        /** @deprecated */
        public Fp(BigInteger q, BigInteger a, BigInteger b) {
            this(q, a, b, (BigInteger)null, (BigInteger)null);
        }

        public Fp(BigInteger q, BigInteger a, BigInteger b, BigInteger order, BigInteger cofactor) {
            this(q, a, b, order, cofactor, false);
        }

        public Fp(BigInteger q, BigInteger a, BigInteger b, BigInteger order, BigInteger cofactor, boolean isInternal) {
            super(q);
            if (isInternal) {
                this.q = q;
                knownQs.add(q);
            } else if (!knownQs.contains(q) && !validatedQs.contains(q)) {
                int maxBitLength = Properties.asInteger("com.mi.car.jsse.easysec.ec.fp_max_size", 1042);
                int certainty = Properties.asInteger("com.mi.car.jsse.easysec.ec.fp_certainty", 100);
                int qBitLength = q.bitLength();
                if (maxBitLength < qBitLength) {
                    throw new IllegalArgumentException("Fp q value out of range");
                }

                if (Primes.hasAnySmallFactors(q) || !Primes.isMRProbablePrime(q, CryptoServicesRegistrar.getSecureRandom(), ECCurve.getNumberOfIterations(qBitLength, certainty))) {
                    throw new IllegalArgumentException("Fp q value not prime");
                }

                validatedQs.add(q);
                this.q = q;
            } else {
                this.q = q;
            }

            this.r = com.mi.car.jsse.easysec.math.ec.ECFieldElement.Fp.calculateResidue(q);
            this.infinity = new com.mi.car.jsse.easysec.math.ec.ECPoint.Fp(this, (ECFieldElement)null, (ECFieldElement)null);
            this.a = this.fromBigInteger(a);
            this.b = this.fromBigInteger(b);
            this.order = order;
            this.cofactor = cofactor;
            this.coord = 4;
        }

        protected Fp(BigInteger q, BigInteger r, ECFieldElement a, ECFieldElement b, BigInteger order, BigInteger cofactor) {
            super(q);
            this.q = q;
            this.r = r;
            this.infinity = new com.mi.car.jsse.easysec.math.ec.ECPoint.Fp(this, (ECFieldElement)null, (ECFieldElement)null);
            this.a = a;
            this.b = b;
            this.order = order;
            this.cofactor = cofactor;
            this.coord = 4;
        }

        protected ECCurve cloneCurve() {
            return new ECCurve.Fp(this.q, this.r, this.a, this.b, this.order, this.cofactor);
        }

        public boolean supportsCoordinateSystem(int coord) {
            switch(coord) {
                case 0:
                case 1:
                case 2:
                case 4:
                    return true;
                case 3:
                default:
                    return false;
            }
        }

        public BigInteger getQ() {
            return this.q;
        }

        public int getFieldSize() {
            return this.q.bitLength();
        }

        public ECFieldElement fromBigInteger(BigInteger x) {
            return new com.mi.car.jsse.easysec.math.ec.ECFieldElement.Fp(this.q, this.r, x);
        }

        protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y) {
            return new com.mi.car.jsse.easysec.math.ec.ECPoint.Fp(this, x, y);
        }

        protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
            return new com.mi.car.jsse.easysec.math.ec.ECPoint.Fp(this, x, y, zs);
        }

        public ECPoint importPoint(ECPoint p) {
            if (this != p.getCurve() && this.getCoordinateSystem() == 2 && !p.isInfinity()) {
                switch(p.getCurve().getCoordinateSystem()) {
                    case 2:
                    case 3:
                    case 4:
                        return new com.mi.car.jsse.easysec.math.ec.ECPoint.Fp(this, this.fromBigInteger(p.x.toBigInteger()), this.fromBigInteger(p.y.toBigInteger()), new ECFieldElement[]{this.fromBigInteger(p.zs[0].toBigInteger())});
                }
            }

            return super.importPoint(p);
        }

        public ECPoint getInfinity() {
            return this.infinity;
        }
    }

    public abstract static class AbstractFp extends ECCurve {
        protected AbstractFp(BigInteger q) {
            super(FiniteFields.getPrimeField(q));
        }

        public boolean isValidFieldElement(BigInteger x) {
            return x != null && x.signum() >= 0 && x.compareTo(this.getField().getCharacteristic()) < 0;
        }

        public ECFieldElement randomFieldElement(SecureRandom r) {
            BigInteger p = this.getField().getCharacteristic();
            ECFieldElement fe1 = this.fromBigInteger(implRandomFieldElement(r, p));
            ECFieldElement fe2 = this.fromBigInteger(implRandomFieldElement(r, p));
            return fe1.multiply(fe2);
        }

        public ECFieldElement randomFieldElementMult(SecureRandom r) {
            BigInteger p = this.getField().getCharacteristic();
            ECFieldElement fe1 = this.fromBigInteger(implRandomFieldElementMult(r, p));
            ECFieldElement fe2 = this.fromBigInteger(implRandomFieldElementMult(r, p));
            return fe1.multiply(fe2);
        }

        protected ECPoint decompressPoint(int yTilde, BigInteger X1) {
            ECFieldElement x = this.fromBigInteger(X1);
            ECFieldElement rhs = x.square().add(this.a).multiply(x).add(this.b);
            ECFieldElement y = rhs.sqrt();
            if (y == null) {
                throw new IllegalArgumentException("Invalid point compression");
            } else {
                if (y.testBitZero() != (yTilde == 1)) {
                    y = y.negate();
                }

                return this.createRawPoint(x, y);
            }
        }

        private static BigInteger implRandomFieldElement(SecureRandom r, BigInteger p) {
            BigInteger x;
            do {
                x = BigIntegers.createRandomBigInteger(p.bitLength(), r);
            } while(x.compareTo(p) >= 0);

            return x;
        }

        private static BigInteger implRandomFieldElementMult(SecureRandom r, BigInteger p) {
            BigInteger x;
            do {
                x = BigIntegers.createRandomBigInteger(p.bitLength(), r);
            } while(x.signum() <= 0 || x.compareTo(p) >= 0);

            return x;
        }
    }

    public class Config {
        protected int coord;
        protected ECEndomorphism endomorphism;
        protected ECMultiplier multiplier;

        Config(int coord, ECEndomorphism endomorphism, ECMultiplier multiplier) {
            this.coord = coord;
            this.endomorphism = endomorphism;
            this.multiplier = multiplier;
        }

        public ECCurve.Config setCoordinateSystem(int coord) {
            this.coord = coord;
            return this;
        }

        public ECCurve.Config setEndomorphism(ECEndomorphism endomorphism) {
            this.endomorphism = endomorphism;
            return this;
        }

        public ECCurve.Config setMultiplier(ECMultiplier multiplier) {
            this.multiplier = multiplier;
            return this;
        }

        public ECCurve create() {
            if (!ECCurve.this.supportsCoordinateSystem(this.coord)) {
                throw new IllegalStateException("unsupported coordinate system");
            } else {
                ECCurve c = ECCurve.this.cloneCurve();
                if (c == ECCurve.this) {
                    throw new IllegalStateException("implementation returned current curve");
                } else {
                    synchronized(c) {
                        c.coord = this.coord;
                        c.endomorphism = this.endomorphism;
                        c.multiplier = this.multiplier;
                        return c;
                    }
                }
            }
        }
    }
}