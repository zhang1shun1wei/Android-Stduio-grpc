package com.mi.car.jsse.easysec.math.ec.custom.djb;

import com.mi.car.jsse.easysec.math.ec.AbstractECLookupTable;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECLookupTable;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.raw.Nat256;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Curve25519 extends ECCurve.AbstractFp {
    private static final int CURVE25519_DEFAULT_COORDS = 4;
    private static final BigInteger C_a = new BigInteger(1, Hex.decodeStrict("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144"));
    private static final BigInteger C_b = new BigInteger(1, Hex.decodeStrict("7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864"));
    public static final BigInteger q = Curve25519FieldElement.Q;
    private static final ECFieldElement[] CURVE25519_AFFINE_ZS = {new Curve25519FieldElement(ECConstants.ONE), new Curve25519FieldElement(C_a)};
    protected Curve25519Point infinity = new Curve25519Point(this, null, null);

    public Curve25519() {
        super(q);
        this.a = fromBigInteger(C_a);
        this.b = fromBigInteger(C_b);
        this.order = new BigInteger(1, Hex.decodeStrict("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"));
        this.cofactor = BigInteger.valueOf(8);
        this.coord = 4;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECCurve cloneCurve() {
        return new Curve25519();
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public boolean supportsCoordinateSystem(int coord) {
        switch (coord) {
            case 4:
                return true;
            default:
                return false;
        }
    }

    public BigInteger getQ() {
        return q;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public int getFieldSize() {
        return q.bitLength();
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement fromBigInteger(BigInteger x) {
        return new Curve25519FieldElement(x);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y) {
        return new Curve25519Point(this, x, y);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        return new Curve25519Point(this, x, y, zs);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len) {
        final int[] table = new int[(len * 8 * 2)];
        int pos = 0;
        for (int i = 0; i < len; i++) {
            ECPoint p = points[off + i];
            Nat256.copy(((Curve25519FieldElement) p.getRawXCoord()).x, 0, table, pos);
            int pos2 = pos + 8;
            Nat256.copy(((Curve25519FieldElement) p.getRawYCoord()).x, 0, table, pos2);
            pos = pos2 + 8;
        }
        return new AbstractECLookupTable() {
            /* class com.mi.car.jsse.easysec.math.ec.custom.djb.Curve25519.AnonymousClass1 */

            @Override // com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public int getSize() {
                return len;
            }

            @Override // com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public ECPoint lookup(int index) {
                int[] x = Nat256.create();
                int[] y = Nat256.create();
                int pos = 0;
                for (int i = 0; i < len; i++) {
                    int MASK = ((i ^ index) - 1) >> 31;
                    for (int j = 0; j < 8; j++) {
                        x[j] = x[j] ^ (table[pos + j] & MASK);
                        y[j] = y[j] ^ (table[(pos + 8) + j] & MASK);
                    }
                    pos += 16;
                }
                return createPoint(x, y);
            }

            @Override // com.mi.car.jsse.easysec.math.ec.AbstractECLookupTable, com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public ECPoint lookupVar(int index) {
                int[] x = Nat256.create();
                int[] y = Nat256.create();
                int pos = index * 8 * 2;
                for (int j = 0; j < 8; j++) {
                    x[j] = table[pos + j];
                    y[j] = table[pos + 8 + j];
                }
                return createPoint(x, y);
            }

            private ECPoint createPoint(int[] x, int[] y) {
                return Curve25519.this.createRawPoint(new Curve25519FieldElement(x), new Curve25519FieldElement(y), Curve25519.CURVE25519_AFFINE_ZS);
            }
        };
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve.AbstractFp, com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement randomFieldElement(SecureRandom r) {
        int[] x = Nat256.create();
        Curve25519Field.random(r, x);
        return new Curve25519FieldElement(x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve.AbstractFp, com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement randomFieldElementMult(SecureRandom r) {
        int[] x = Nat256.create();
        Curve25519Field.randomMult(r, x);
        return new Curve25519FieldElement(x);
    }
}
