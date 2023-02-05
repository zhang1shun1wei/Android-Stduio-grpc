package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.AbstractECLookupTable;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECLookupTable;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.raw.Nat256;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.math.BigInteger;

public class SecT193R1Curve extends ECCurve.AbstractF2m {
    private static final ECFieldElement[] SECT193R1_AFFINE_ZS = {new SecT193FieldElement(ECConstants.ONE)};
    private static final int SECT193R1_DEFAULT_COORDS = 6;
    protected SecT193R1Point infinity = new SecT193R1Point(this, null, null);

    public SecT193R1Curve() {
        super(193, 15, 0, 0);
        this.a = fromBigInteger(new BigInteger(1, Hex.decodeStrict("0017858FEB7A98975169E171F77B4087DE098AC8A911DF7B01")));
        this.b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("00FDFB49BFE6C3A89FACADAA7A1E5BBC7CC1C2E5D831478814")));
        this.order = new BigInteger(1, Hex.decodeStrict("01000000000000000000000000C7F34A778F443ACC920EBA49"));
        this.cofactor = BigInteger.valueOf(2);
        this.coord = 6;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECCurve cloneCurve() {
        return new SecT193R1Curve();
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public boolean supportsCoordinateSystem(int coord) {
        switch (coord) {
            case 6:
                return true;
            default:
                return false;
        }
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public int getFieldSize() {
        return 193;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement fromBigInteger(BigInteger x) {
        return new SecT193FieldElement(x);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y) {
        return new SecT193R1Point(this, x, y);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        return new SecT193R1Point(this, x, y, zs);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve.AbstractF2m
    public boolean isKoblitz() {
        return false;
    }

    public int getM() {
        return 193;
    }

    public boolean isTrinomial() {
        return true;
    }

    public int getK1() {
        return 15;
    }

    public int getK2() {
        return 0;
    }

    public int getK3() {
        return 0;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len) {
        final long[] table = new long[(len * 4 * 2)];
        int pos = 0;
        for (int i = 0; i < len; i++) {
            ECPoint p = points[off + i];
            Nat256.copy64(((SecT193FieldElement) p.getRawXCoord()).x, 0, table, pos);
            int pos2 = pos + 4;
            Nat256.copy64(((SecT193FieldElement) p.getRawYCoord()).x, 0, table, pos2);
            pos = pos2 + 4;
        }
        return new AbstractECLookupTable() {
            /* class com.mi.car.jsse.easysec.math.ec.custom.sec.SecT193R1Curve.AnonymousClass1 */

            @Override // com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public int getSize() {
                return len;
            }

            @Override // com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public ECPoint lookup(int index) {
                long[] x = Nat256.create64();
                long[] y = Nat256.create64();
                int pos = 0;
                for (int i = 0; i < len; i++) {
                    long MASK = (long) (((i ^ index) - 1) >> 31);
                    for (int j = 0; j < 4; j++) {
                        x[j] = x[j] ^ (table[pos + j] & MASK);
                        y[j] = y[j] ^ (table[(pos + 4) + j] & MASK);
                    }
                    pos += 8;
                }
                return createPoint(x, y);
            }

            @Override // com.mi.car.jsse.easysec.math.ec.AbstractECLookupTable, com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public ECPoint lookupVar(int index) {
                long[] x = Nat256.create64();
                long[] y = Nat256.create64();
                int pos = index * 4 * 2;
                for (int j = 0; j < 4; j++) {
                    x[j] = table[pos + j];
                    y[j] = table[pos + 4 + j];
                }
                return createPoint(x, y);
            }

            private ECPoint createPoint(long[] x, long[] y) {
                return SecT193R1Curve.this.createRawPoint(new SecT193FieldElement(x), new SecT193FieldElement(y), SecT193R1Curve.SECT193R1_AFFINE_ZS);
            }
        };
    }
}
