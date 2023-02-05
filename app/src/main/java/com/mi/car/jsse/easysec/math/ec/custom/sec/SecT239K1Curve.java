package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.AbstractECLookupTable;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECLookupTable;
import com.mi.car.jsse.easysec.math.ec.ECMultiplier;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.ec.WTauNafMultiplier;
import com.mi.car.jsse.easysec.math.raw.Nat256;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.math.BigInteger;

public class SecT239K1Curve extends ECCurve.AbstractF2m {
    private static final ECFieldElement[] SECT239K1_AFFINE_ZS = {new SecT239FieldElement(ECConstants.ONE)};
    private static final int SECT239K1_DEFAULT_COORDS = 6;
    protected SecT239K1Point infinity = new SecT239K1Point(this, null, null);

    public SecT239K1Curve() {
        super(239, 158, 0, 0);
        this.a = fromBigInteger(BigInteger.valueOf(0));
        this.b = fromBigInteger(BigInteger.valueOf(1));
        this.order = new BigInteger(1, Hex.decodeStrict("2000000000000000000000000000005A79FEC67CB6E91F1C1DA800E478A5"));
        this.cofactor = BigInteger.valueOf(4);
        this.coord = 6;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECCurve cloneCurve() {
        return new SecT239K1Curve();
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

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECMultiplier createDefaultMultiplier() {
        return new WTauNafMultiplier();
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public int getFieldSize() {
        return 239;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement fromBigInteger(BigInteger x) {
        return new SecT239FieldElement(x);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y) {
        return new SecT239K1Point(this, x, y);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        return new SecT239K1Point(this, x, y, zs);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve.AbstractF2m
    public boolean isKoblitz() {
        return true;
    }

    public int getM() {
        return 239;
    }

    public boolean isTrinomial() {
        return true;
    }

    public int getK1() {
        return 158;
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
            Nat256.copy64(((SecT239FieldElement) p.getRawXCoord()).x, 0, table, pos);
            int pos2 = pos + 4;
            Nat256.copy64(((SecT239FieldElement) p.getRawYCoord()).x, 0, table, pos2);
            pos = pos2 + 4;
        }
        return new AbstractECLookupTable() {
            /* class com.mi.car.jsse.easysec.math.ec.custom.sec.SecT239K1Curve.AnonymousClass1 */

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
                return SecT239K1Curve.this.createRawPoint(new SecT239FieldElement(x), new SecT239FieldElement(y), SecT239K1Curve.SECT239K1_AFFINE_ZS);
            }
        };
    }
}
