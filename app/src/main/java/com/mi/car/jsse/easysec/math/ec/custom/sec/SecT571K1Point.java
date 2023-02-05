package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.raw.Nat576;

public class SecT571K1Point extends ECPoint.AbstractF2m {
    SecT571K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y) {
        super(curve, x, y);
    }

    SecT571K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        super(curve, x, y, zs);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint detach() {
        return new SecT571K1Point(null, getAffineXCoord(), getAffineYCoord());
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECFieldElement getYCoord() {
        ECFieldElement X = this.x;
        ECFieldElement L = this.y;
        if (isInfinity() || X.isZero()) {
            return L;
        }
        ECFieldElement Y = L.add(X).multiply(X);
        ECFieldElement Z = this.zs[0];
        if (!Z.isOne()) {
            return Y.divide(Z);
        }
        return Y;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public boolean getCompressionYTilde() {
        ECFieldElement X = getRawXCoord();
        if (!X.isZero() && getRawYCoord().testBitZero() != X.testBitZero()) {
            return true;
        }
        return false;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint add(ECPoint b) {
        long[] U2;
        long[] S2;
        long[] U1;
        long[] S1;
        SecT571FieldElement X3;
        SecT571FieldElement Z3;
        SecT571FieldElement L3;
        if (isInfinity()) {
            return b;
        }
        if (b.isInfinity()) {
            return this;
        }
        ECCurve curve = getCurve();
        SecT571FieldElement X1 = (SecT571FieldElement) this.x;
        SecT571FieldElement X2 = (SecT571FieldElement) b.getRawXCoord();
        if (!X1.isZero()) {
            SecT571FieldElement L1 = (SecT571FieldElement) this.y;
            SecT571FieldElement Z1 = (SecT571FieldElement) this.zs[0];
            SecT571FieldElement L2 = (SecT571FieldElement) b.getRawYCoord();
            SecT571FieldElement Z2 = (SecT571FieldElement) b.getZCoord(0);
            long[] t1 = Nat576.create64();
            long[] t2 = Nat576.create64();
            long[] t3 = Nat576.create64();
            long[] t4 = Nat576.create64();
            long[] Z1Precomp = Z1.isOne() ? null : SecT571Field.precompMultiplicand(Z1.x);
            if (Z1Precomp == null) {
                U2 = X2.x;
                S2 = L2.x;
            } else {
                U2 = t2;
                SecT571Field.multiplyPrecomp(X2.x, Z1Precomp, t2);
                S2 = t4;
                SecT571Field.multiplyPrecomp(L2.x, Z1Precomp, t4);
            }
            long[] Z2Precomp = Z2.isOne() ? null : SecT571Field.precompMultiplicand(Z2.x);
            if (Z2Precomp == null) {
                U1 = X1.x;
                S1 = L1.x;
            } else {
                U1 = t1;
                SecT571Field.multiplyPrecomp(X1.x, Z2Precomp, t1);
                S1 = t3;
                SecT571Field.multiplyPrecomp(L1.x, Z2Precomp, t3);
            }
            SecT571Field.add(S1, S2, t3);
            SecT571Field.add(U1, U2, t4);
            if (!Nat576.isZero64(t4)) {
                if (X2.isZero()) {
                    ECPoint p = normalize();
                    SecT571FieldElement X12 = (SecT571FieldElement) p.getXCoord();
                    ECFieldElement Y1 = p.getYCoord();
                    ECFieldElement L = Y1.add(L2).divide(X12);
                    X3 = (SecT571FieldElement) L.square().add(L).add(X12);
                    if (X3.isZero()) {
                        return new SecT571K1Point(curve, X3, curve.getB());
                    }
                    L3 = (SecT571FieldElement) L.multiply(X12.add(X3)).add(X3).add(Y1).divide(X3).add(X3);
                    Z3 = (SecT571FieldElement) curve.fromBigInteger(ECConstants.ONE);
                } else {
                    SecT571Field.square(t4, t4);
                    long[] APrecomp = SecT571Field.precompMultiplicand(t3);
                    SecT571Field.multiplyPrecomp(U1, APrecomp, t1);
                    SecT571Field.multiplyPrecomp(U2, APrecomp, t2);
                    X3 = new SecT571FieldElement(t1);
                    SecT571Field.multiply(t1, t2, X3.x);
                    if (X3.isZero()) {
                        return new SecT571K1Point(curve, X3, curve.getB());
                    }
                    Z3 = new SecT571FieldElement(t3);
                    SecT571Field.multiplyPrecomp(t4, APrecomp, Z3.x);
                    if (Z2Precomp != null) {
                        SecT571Field.multiplyPrecomp(Z3.x, Z2Precomp, Z3.x);
                    }
                    long[] tt = Nat576.createExt64();
                    SecT571Field.add(t2, t4, t4);
                    SecT571Field.squareAddToExt(t4, tt);
                    SecT571Field.add(L1.x, Z1.x, t4);
                    SecT571Field.multiplyAddToExt(t4, Z3.x, tt);
                    L3 = new SecT571FieldElement(t4);
                    SecT571Field.reduce(tt, L3.x);
                    if (Z1Precomp != null) {
                        SecT571Field.multiplyPrecomp(Z3.x, Z1Precomp, Z3.x);
                    }
                }
                return new SecT571K1Point(curve, X3, L3, new ECFieldElement[]{Z3});
            } else if (Nat576.isZero64(t3)) {
                return twice();
            } else {
                return curve.getInfinity();
            }
        } else if (X2.isZero()) {
            return curve.getInfinity();
        } else {
            return b.add(this);
        }
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint twice() {
        ECFieldElement T;
        if (isInfinity()) {
            return this;
        }
        ECCurve curve = getCurve();
        ECFieldElement X1 = this.x;
        if (X1.isZero()) {
            return curve.getInfinity();
        }
        ECFieldElement L1 = this.y;
        ECFieldElement Z1 = this.zs[0];
        boolean Z1IsOne = Z1.isOne();
        ECFieldElement Z1Sq = Z1IsOne ? Z1 : Z1.square();
        if (Z1IsOne) {
            T = L1.square().add(L1);
        } else {
            T = L1.add(Z1).multiply(L1);
        }
        if (T.isZero()) {
            return new SecT571K1Point(curve, T, curve.getB());
        }
        ECFieldElement X3 = T.square();
        ECFieldElement Z3 = Z1IsOne ? T : T.multiply(Z1Sq);
        ECFieldElement t1 = L1.add(X1).square();
        return new SecT571K1Point(curve, X3, t1.add(T).add(Z1Sq).multiply(t1).add(Z1IsOne ? Z1 : Z1Sq.square()).add(X3).add(Z3), new ECFieldElement[]{Z3});
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint twicePlus(ECPoint b) {
        if (isInfinity()) {
            return b;
        }
        if (b.isInfinity()) {
            return twice();
        }
        ECCurve curve = getCurve();
        ECFieldElement X1 = this.x;
        if (X1.isZero()) {
            return b;
        }
        ECFieldElement X2 = b.getRawXCoord();
        ECFieldElement Z2 = b.getZCoord(0);
        if (X2.isZero() || !Z2.isOne()) {
            return twice().add(b);
        }
        ECFieldElement L1 = this.y;
        ECFieldElement Z1 = this.zs[0];
        ECFieldElement L2 = b.getRawYCoord();
        ECFieldElement X1Sq = X1.square();
        ECFieldElement L1Sq = L1.square();
        ECFieldElement Z1Sq = Z1.square();
        ECFieldElement T = L1Sq.add(L1.multiply(Z1));
        ECFieldElement L2plus1 = L2.addOne();
        ECFieldElement A = L2plus1.multiply(Z1Sq).add(L1Sq).multiplyPlusProduct(T, X1Sq, Z1Sq);
        ECFieldElement X2Z1Sq = X2.multiply(Z1Sq);
        ECFieldElement B = X2Z1Sq.add(T).square();
        if (B.isZero()) {
            if (A.isZero()) {
                return b.twice();
            }
            return curve.getInfinity();
        } else if (A.isZero()) {
            return new SecT571K1Point(curve, A, curve.getB());
        } else {
            ECFieldElement X3 = A.square().multiply(X2Z1Sq);
            ECFieldElement Z3 = A.multiply(B).multiply(Z1Sq);
            return new SecT571K1Point(curve, X3, A.add(B).square().multiplyPlusProduct(T, L2plus1, Z3), new ECFieldElement[]{Z3});
        }
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint negate() {
        if (isInfinity()) {
            return this;
        }
        ECFieldElement X = this.x;
        if (X.isZero()) {
            return this;
        }
        ECFieldElement L = this.y;
        ECFieldElement Z = this.zs[0];
        return new SecT571K1Point(this.curve, X, L.add(Z), new ECFieldElement[]{Z});
    }
}
