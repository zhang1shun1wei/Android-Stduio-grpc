package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.AbstractECLookupTable;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECLookupTable;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SecP384R1Curve extends ECCurve.AbstractFp {
    private static final ECFieldElement[] SECP384R1_AFFINE_ZS = {new SecP384R1FieldElement(ECConstants.ONE)};
    private static final int SECP384R1_DEFAULT_COORDS = 2;
    public static final BigInteger q = SecP384R1FieldElement.Q;
    protected SecP384R1Point infinity = new SecP384R1Point(this, null, null);

    public SecP384R1Curve() {
        super(q);
        this.a = fromBigInteger(new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC")));
        this.b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF")));
        this.order = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"));
        this.cofactor = BigInteger.valueOf(1);
        this.coord = 2;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECCurve cloneCurve() {
        return new SecP384R1Curve();
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
        return new SecP384R1FieldElement(x);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y) {
        return new SecP384R1Point(this, x, y);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        return new SecP384R1Point(this, x, y, zs);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len) {
        final int[] table = new int[(len * 12 * 2)];
        int pos = 0;
        for (int i = 0; i < len; i++) {
            ECPoint p = points[off + i];
            Nat.copy(12, ((SecP384R1FieldElement) p.getRawXCoord()).x, 0, table, pos);
            int pos2 = pos + 12;
            Nat.copy(12, ((SecP384R1FieldElement) p.getRawYCoord()).x, 0, table, pos2);
            pos = pos2 + 12;
        }
        return new AbstractECLookupTable() {
            /* class com.mi.car.jsse.easysec.math.ec.custom.sec.SecP384R1Curve.AnonymousClass1 */

            @Override // com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public int getSize() {
                return len;
            }

            @Override // com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public ECPoint lookup(int index) {
                int[] x = Nat.create(12);
                int[] y = Nat.create(12);
                int pos = 0;
                for (int i = 0; i < len; i++) {
                    int MASK = ((i ^ index) - 1) >> 31;
                    for (int j = 0; j < 12; j++) {
                        x[j] = x[j] ^ (table[pos + j] & MASK);
                        y[j] = y[j] ^ (table[(pos + 12) + j] & MASK);
                    }
                    pos += 24;
                }
                return createPoint(x, y);
            }

            @Override // com.mi.car.jsse.easysec.math.ec.AbstractECLookupTable, com.mi.car.jsse.easysec.math.ec.ECLookupTable
            public ECPoint lookupVar(int index) {
                int[] x = Nat.create(12);
                int[] y = Nat.create(12);
                int pos = index * 12 * 2;
                for (int j = 0; j < 12; j++) {
                    x[j] = table[pos + j];
                    y[j] = table[pos + 12 + j];
                }
                return createPoint(x, y);
            }

            private ECPoint createPoint(int[] x, int[] y) {
                return SecP384R1Curve.this.createRawPoint(new SecP384R1FieldElement(x), new SecP384R1FieldElement(y), SecP384R1Curve.SECP384R1_AFFINE_ZS);
            }
        };
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve.AbstractFp, com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement randomFieldElement(SecureRandom r) {
        int[] x = Nat.create(12);
        SecP384R1Field.random(r, x);
        return new SecP384R1FieldElement(x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve.AbstractFp, com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement randomFieldElementMult(SecureRandom r) {
        int[] x = Nat.create(12);
        SecP384R1Field.randomMult(r, x);
        return new SecP384R1FieldElement(x);
    }
}
