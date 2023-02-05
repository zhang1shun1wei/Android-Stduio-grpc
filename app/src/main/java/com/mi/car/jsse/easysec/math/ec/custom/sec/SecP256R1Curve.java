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
import java.security.SecureRandom;

public class SecP256R1Curve extends ECCurve.AbstractFp {
    private static final ECFieldElement[] SECP256R1_AFFINE_ZS = {new SecP256R1FieldElement(ECConstants.ONE)};
    private static final int SECP256R1_DEFAULT_COORDS = 2;
    public static final BigInteger q = SecP256R1FieldElement.Q;
    protected SecP256R1Point infinity = new SecP256R1Point(this, null, null);

    public SecP256R1Curve() {
        super(q);
        this.a = fromBigInteger(new BigInteger(1, Hex.decodeStrict("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC")));
        this.b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")));
        this.order = new BigInteger(1, Hex.decodeStrict("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"));
        this.cofactor = BigInteger.valueOf(1);
        this.coord = 2;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECCurve cloneCurve() {
        return new SecP256R1Curve();
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
        return new SecP256R1FieldElement(x);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y) {
        return new SecP256R1Point(this, x, y);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        return new SecP256R1Point(this, x, y, zs);
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
            Nat256.copy(((SecP256R1FieldElement) p.getRawXCoord()).x, 0, table, pos);
            int pos2 = pos + 8;
            Nat256.copy(((SecP256R1FieldElement) p.getRawYCoord()).x, 0, table, pos2);
            pos = pos2 + 8;
        }
        return new AbstractECLookupTable() {
            /* class com.mi.car.jsse.easysec.math.ec.custom.sec.SecP256R1Curve.AnonymousClass1 */

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
                return SecP256R1Curve.this.createRawPoint(new SecP256R1FieldElement(x), new SecP256R1FieldElement(y), SecP256R1Curve.SECP256R1_AFFINE_ZS);
            }
        };
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve.AbstractFp, com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement randomFieldElement(SecureRandom r) {
        int[] x = Nat256.create();
        SecP256R1Field.random(r, x);
        return new SecP256R1FieldElement(x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve.AbstractFp, com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement randomFieldElementMult(SecureRandom r) {
        int[] x = Nat256.create();
        SecP256R1Field.randomMult(r, x);
        return new SecP256R1FieldElement(x);
    }
}
