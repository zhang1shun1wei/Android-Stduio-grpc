package com.mi.car.jsse.easysec.math.ec.custom.gm;

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

public class SM2P256V1Curve extends ECCurve.AbstractFp {
    private static final ECFieldElement[] SM2P256V1_AFFINE_ZS = {new SM2P256V1FieldElement(ECConstants.ONE)};
    private static final int SM2P256V1_DEFAULT_COORDS = 2;
    public static final BigInteger q = SM2P256V1FieldElement.Q;
    protected SM2P256V1Point infinity = new SM2P256V1Point(this, null, null);

    public SM2P256V1Curve() {
        super(q);
        this.a = fromBigInteger(new BigInteger(1, Hex.decodeStrict("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")));
        this.b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93")));
        this.order = new BigInteger(1, Hex.decodeStrict("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"));
        this.cofactor = BigInteger.valueOf(1);
        this.coord = 2;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECCurve cloneCurve() {
        return new SM2P256V1Curve();
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
        return new SM2P256V1FieldElement(x);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y) {
        return new SM2P256V1Point(this, x, y);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        return new SM2P256V1Point(this, x, y, zs);
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
            Nat256.copy(((SM2P256V1FieldElement) p.getRawXCoord()).x, 0, table, pos);
            int pos2 = pos + 8;
            Nat256.copy(((SM2P256V1FieldElement) p.getRawYCoord()).x, 0, table, pos2);
            pos = pos2 + 8;
        }
        return new AbstractECLookupTable() {
            /* class com.mi.car.jsse.easysec.math.ec.custom.gm.SM2P256V1Curve.AnonymousClass1 */

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
                return SM2P256V1Curve.this.createRawPoint(new SM2P256V1FieldElement(x), new SM2P256V1FieldElement(y), SM2P256V1Curve.SM2P256V1_AFFINE_ZS);
            }
        };
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve.AbstractFp, com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement randomFieldElement(SecureRandom r) {
        int[] x = Nat256.create();
        SM2P256V1Field.random(r, x);
        return new SM2P256V1FieldElement(x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECCurve.AbstractFp, com.mi.car.jsse.easysec.math.ec.ECCurve
    public ECFieldElement randomFieldElementMult(SecureRandom r) {
        int[] x = Nat256.create();
        SM2P256V1Field.randomMult(r, x);
        return new SM2P256V1FieldElement(x);
    }
}
