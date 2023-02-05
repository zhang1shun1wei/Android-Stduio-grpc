package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat160;

public class SecP160K1Point extends ECPoint.AbstractFp {
    SecP160K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y) {
        super(curve, x, y);
    }

    SecP160K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        super(curve, x, y, zs);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint detach() {
        return new SecP160K1Point(null, getAffineXCoord(), getAffineYCoord());
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint add(ECPoint b) {
        int[] S2;
        int[] U2;
        int[] S1;
        int[] U1;
        if (isInfinity()) {
            return b;
        }
        if (b.isInfinity()) {
            return this;
        }
        if (this == b) {
            return twice();
        }
        ECCurve curve = getCurve();
        SecP160R2FieldElement X1 = (SecP160R2FieldElement) this.x;
        SecP160R2FieldElement Y1 = (SecP160R2FieldElement) this.y;
        SecP160R2FieldElement X2 = (SecP160R2FieldElement) b.getXCoord();
        SecP160R2FieldElement Y2 = (SecP160R2FieldElement) b.getYCoord();
        SecP160R2FieldElement Z1 = (SecP160R2FieldElement) this.zs[0];
        SecP160R2FieldElement Z2 = (SecP160R2FieldElement) b.getZCoord(0);
        int[] tt1 = Nat160.createExt();
        int[] t2 = Nat160.create();
        int[] t3 = Nat160.create();
        int[] t4 = Nat160.create();
        boolean Z1IsOne = Z1.isOne();
        if (Z1IsOne) {
            U2 = X2.x;
            S2 = Y2.x;
        } else {
            S2 = t3;
            SecP160R2Field.square(Z1.x, S2);
            U2 = t2;
            SecP160R2Field.multiply(S2, X2.x, U2);
            SecP160R2Field.multiply(S2, Z1.x, S2);
            SecP160R2Field.multiply(S2, Y2.x, S2);
        }
        boolean Z2IsOne = Z2.isOne();
        if (Z2IsOne) {
            U1 = X1.x;
            S1 = Y1.x;
        } else {
            S1 = t4;
            SecP160R2Field.square(Z2.x, S1);
            U1 = tt1;
            SecP160R2Field.multiply(S1, X1.x, U1);
            SecP160R2Field.multiply(S1, Z2.x, S1);
            SecP160R2Field.multiply(S1, Y1.x, S1);
        }
        int[] H = Nat160.create();
        SecP160R2Field.subtract(U1, U2, H);
        SecP160R2Field.subtract(S1, S2, t2);
        if (!Nat160.isZero(H)) {
            SecP160R2Field.square(H, t3);
            int[] G = Nat160.create();
            SecP160R2Field.multiply(t3, H, G);
            SecP160R2Field.multiply(t3, U1, t3);
            SecP160R2Field.negate(G, G);
            Nat160.mul(S1, G, tt1);
            SecP160R2Field.reduce32(Nat160.addBothTo(t3, t3, G), G);
            SecP160R2FieldElement X3 = new SecP160R2FieldElement(t4);
            SecP160R2Field.square(t2, X3.x);
            SecP160R2Field.subtract(X3.x, G, X3.x);
            SecP160R2FieldElement Y3 = new SecP160R2FieldElement(G);
            SecP160R2Field.subtract(t3, X3.x, Y3.x);
            SecP160R2Field.multiplyAddToExt(Y3.x, t2, tt1);
            SecP160R2Field.reduce(tt1, Y3.x);
            SecP160R2FieldElement Z3 = new SecP160R2FieldElement(H);
            if (!Z1IsOne) {
                SecP160R2Field.multiply(Z3.x, Z1.x, Z3.x);
            }
            if (!Z2IsOne) {
                SecP160R2Field.multiply(Z3.x, Z2.x, Z3.x);
            }
            return new SecP160K1Point(curve, X3, Y3, new ECFieldElement[]{Z3});
        } else if (Nat160.isZero(t2)) {
            return twice();
        } else {
            return curve.getInfinity();
        }
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint twice() {
        if (isInfinity()) {
            return this;
        }
        ECCurve curve = getCurve();
        SecP160R2FieldElement Y1 = (SecP160R2FieldElement) this.y;
        if (Y1.isZero()) {
            return curve.getInfinity();
        }
        SecP160R2FieldElement X1 = (SecP160R2FieldElement) this.x;
        SecP160R2FieldElement Z1 = (SecP160R2FieldElement) this.zs[0];
        int[] Y1Squared = Nat160.create();
        SecP160R2Field.square(Y1.x, Y1Squared);
        int[] T = Nat160.create();
        SecP160R2Field.square(Y1Squared, T);
        int[] M = Nat160.create();
        SecP160R2Field.square(X1.x, M);
        SecP160R2Field.reduce32(Nat160.addBothTo(M, M, M), M);
        SecP160R2Field.multiply(Y1Squared, X1.x, Y1Squared);
        SecP160R2Field.reduce32(Nat.shiftUpBits(5, Y1Squared, 2, 0), Y1Squared);
        int[] t1 = Nat160.create();
        SecP160R2Field.reduce32(Nat.shiftUpBits(5, T, 3, 0, t1), t1);
        SecP160R2FieldElement X3 = new SecP160R2FieldElement(T);
        SecP160R2Field.square(M, X3.x);
        SecP160R2Field.subtract(X3.x, Y1Squared, X3.x);
        SecP160R2Field.subtract(X3.x, Y1Squared, X3.x);
        SecP160R2FieldElement Y3 = new SecP160R2FieldElement(Y1Squared);
        SecP160R2Field.subtract(Y1Squared, X3.x, Y3.x);
        SecP160R2Field.multiply(Y3.x, M, Y3.x);
        SecP160R2Field.subtract(Y3.x, t1, Y3.x);
        SecP160R2FieldElement Z3 = new SecP160R2FieldElement(M);
        SecP160R2Field.twice(Y1.x, Z3.x);
        if (!Z1.isOne()) {
            SecP160R2Field.multiply(Z3.x, Z1.x, Z3.x);
        }
        return new SecP160K1Point(curve, X3, Y3, new ECFieldElement[]{Z3});
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint twicePlus(ECPoint b) {
        if (this == b) {
            return threeTimes();
        }
        if (isInfinity()) {
            return b;
        }
        if (b.isInfinity()) {
            return twice();
        }
        return !this.y.isZero() ? twice().add(b) : b;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint threeTimes() {
        return (isInfinity() || this.y.isZero()) ? this : twice().add(this);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint negate() {
        return isInfinity() ? this : new SecP160K1Point(this.curve, this.x, this.y.negate(), this.zs);
    }
}
