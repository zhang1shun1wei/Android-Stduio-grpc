package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.AbstractECLookupTable;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECLookupTable;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.raw.Nat160;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SecP160R1Curve extends ECCurve.AbstractFp {
    private static final ECFieldElement[] SECP160R1_AFFINE_ZS = {new SecP160R1FieldElement(ECConstants.ONE)};
    private static final int SECP160R1_DEFAULT_COORDS = 2;
    public static final BigInteger q = SecP160R1FieldElement.Q;
    protected SecP160R1Point infinity = new SecP160R1Point(this, null, null);

    public SecP160R1Curve() {
        super(q);
        this.a = fromBigInteger(new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC")));
        this.b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45")));
        this.order = new BigInteger(1, Hex.decodeStrict("0100000000000000000001F4C8F927AED3CA752257"));
        this.cofactor = BigInteger.valueOf(1);
        this.coord = 2;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECCurve cloneCurve() {
        return new SecP160R1Curve();
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public boolean supportsCoordinateSystem(int coord) {
        switch (coord) {
            case 2:
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
        return new SecP160R1FieldElement(x);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y) {
        return new SecP160R1Point(this, x, y);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        return new SecP160R1Point(this, x, y, zs);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len) {
        final int[] table = new int[(len * 5 * 2)];
        int pos = 0;
        for (int i = 0; i < len; i++) {
            ECPoint p = points[off + i];
            Nat160.copy(((SecP160R1FieldElement) p.getRawXCoord()).x, 0, table, pos);
            int pos2 = pos + 5;
            Nat160.copy(((SecP160R1FieldElement) p.getRawYCoord()).x, 0, table, pos2);
            pos = pos2 + 5;
        }
        return new AbstractECLookupTable() {
            /* class com.mi.car.jsse.easysec.math.ec.custom.sec.SecP160R1Curve.AnonymousClass1 */

            @Override // com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public int getSize() {
                return len;
            }

            @Override // com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public ECPoint lookup(int index) {
                int[] x = Nat160.create();
                int[] y = Nat160.create();
                int pos = 0;
                for (int i = 0; i < len; i++) {
                    int MASK = ((i ^ index) - 1) >> 31;
                    for (int j = 0; j < 5; j++) {
                        x[j] = x[j] ^ (table[pos + j] & MASK);
                        y[j] = y[j] ^ (table[(pos + 5) + j] & MASK);
                    }
                    pos += 10;
                }
                return createPoint(x, y);
            }

            @Override // com.mi.car.jsse.easysec.math.ec.AbstractECLookupTable, com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public ECPoint lookupVar(int index) {
                int[] x = Nat160.create();
                int[] y = Nat160.create();
                int pos = index * 5 * 2;
                for (int j = 0; j < 5; j++) {
                    x[j] = table[pos + j];
                    y[j] = table[pos + 5 + j];
                }
                return createPoint(x, y);
            }

            private ECPoint createPoint(int[] x, int[] y) {
                return SecP160R1Curve.this.createRawPoint(new SecP160R1FieldElement(x), new SecP160R1FieldElement(y), SecP160R1Curve.SECP160R1_AFFINE_ZS);
            }
        };
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve.AbstractFp, com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement randomFieldElement(SecureRandom r) {
        int[] x = Nat160.create();
        SecP160R1Field.random(r, x);
        return new SecP160R1FieldElement(x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve.AbstractFp, com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement randomFieldElementMult(SecureRandom r) {
        int[] x = Nat160.create();
        SecP160R1Field.randomMult(r, x);
        return new SecP160R1FieldElement(x);
    }
}
