package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.AbstractECLookupTable;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECLookupTable;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.raw.Nat128;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.math.BigInteger;

public class SecT113R1Curve extends ECCurve.AbstractF2m {
    private static final ECFieldElement[] SECT113R1_AFFINE_ZS = {new SecT113FieldElement(ECConstants.ONE)};
    private static final int SECT113R1_DEFAULT_COORDS = 6;
    protected SecT113R1Point infinity = new SecT113R1Point(this, null, null);

    public SecT113R1Curve() {
        super(113, 9, 0, 0);
        this.a = fromBigInteger(new BigInteger(1, Hex.decodeStrict("003088250CA6E7C7FE649CE85820F7")));
        this.b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("00E8BEE4D3E2260744188BE0E9C723")));
        this.order = new BigInteger(1, Hex.decodeStrict("0100000000000000D9CCEC8A39E56F"));
        this.cofactor = BigInteger.valueOf(2);
        this.coord = 6;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECCurve cloneCurve() {
        return new SecT113R1Curve();
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
        return 113;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement fromBigInteger(BigInteger x) {
        return new SecT113FieldElement(x);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y) {
        return new SecT113R1Point(this, x, y);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        return new SecT113R1Point(this, x, y, zs);
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
        return 113;
    }

    public boolean isTrinomial() {
        return true;
    }

    public int getK1() {
        return 9;
    }

    public int getK2() {
        return 0;
    }

    public int getK3() {
        return 0;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len) {
        final long[] table = new long[(len * 2 * 2)];
        int pos = 0;
        for (int i = 0; i < len; i++) {
            ECPoint p = points[off + i];
            Nat128.copy64(((SecT113FieldElement) p.getRawXCoord()).x, 0, table, pos);
            int pos2 = pos + 2;
            Nat128.copy64(((SecT113FieldElement) p.getRawYCoord()).x, 0, table, pos2);
            pos = pos2 + 2;
        }
        return new AbstractECLookupTable() {
            /* class com.mi.car.jsse.easysec.math.ec.custom.sec.SecT113R1Curve.AnonymousClass1 */

            @Override // com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public int getSize() {
                return len;
            }

            @Override // com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public ECPoint lookup(int index) {
                long[] x = Nat128.create64();
                long[] y = Nat128.create64();
                int pos = 0;
                for (int i = 0; i < len; i++) {
                    long MASK = (long) (((i ^ index) - 1) >> 31);
                    for (int j = 0; j < 2; j++) {
                        x[j] = x[j] ^ (table[pos + j] & MASK);
                        y[j] = y[j] ^ (table[(pos + 2) + j] & MASK);
                    }
                    pos += 4;
                }
                return createPoint(x, y);
            }

            @Override // com.mi.car.jsse.easysec.math.ec.AbstractECLookupTable, com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public ECPoint lookupVar(int index) {
                long[] x = Nat128.create64();
                long[] y = Nat128.create64();
                int pos = index * 2 * 2;
                for (int j = 0; j < 2; j++) {
                    x[j] = table[pos + j];
                    y[j] = table[pos + 2 + j];
                }
                return createPoint(x, y);
            }

            private ECPoint createPoint(long[] x, long[] y) {
                return SecT113R1Curve.this.createRawPoint(new SecT113FieldElement(x), new SecT113FieldElement(y), SecT113R1Curve.SECT113R1_AFFINE_ZS);
            }
        };
    }
}
