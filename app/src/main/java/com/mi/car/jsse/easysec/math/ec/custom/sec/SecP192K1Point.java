package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat192;

public class SecP192K1Point extends ECPoint.AbstractFp {
    SecP192K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y) {
        super(curve, x, y);
    }

    SecP192K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        super(curve, x, y, zs);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint detach() {
        return new SecP192K1Point(null, getAffineXCoord(), getAffineYCoord());
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
        SecP192K1FieldElement X1 = (SecP192K1FieldElement) this.x;
        SecP192K1FieldElement Y1 = (SecP192K1FieldElement) this.y;
        SecP192K1FieldElement X2 = (SecP192K1FieldElement) b.getXCoord();
        SecP192K1FieldElement Y2 = (SecP192K1FieldElement) b.getYCoord();
        SecP192K1FieldElement Z1 = (SecP192K1FieldElement) this.zs[0];
        SecP192K1FieldElement Z2 = (SecP192K1FieldElement) b.getZCoord(0);
        int[] tt1 = Nat192.createExt();
        int[] t2 = Nat192.create();
        int[] t3 = Nat192.create();
        int[] t4 = Nat192.create();
        boolean Z1IsOne = Z1.isOne();
        if (Z1IsOne) {
            U2 = X2.x;
            S2 = Y2.x;
        } else {
            S2 = t3;
            SecP192K1Field.square(Z1.x, S2);
            U2 = t2;
            SecP192K1Field.multiply(S2, X2.x, U2);
            SecP192K1Field.multiply(S2, Z1.x, S2);
            SecP192K1Field.multiply(S2, Y2.x, S2);
        }
        boolean Z2IsOne = Z2.isOne();
        if (Z2IsOne) {
            U1 = X1.x;
            S1 = Y1.x;
        } else {
            S1 = t4;
            SecP192K1Field.square(Z2.x, S1);
            U1 = tt1;
            SecP192K1Field.multiply(S1, X1.x, U1);
            SecP192K1Field.multiply(S1, Z2.x, S1);
            SecP192K1Field.multiply(S1, Y1.x, S1);
        }
        int[] H = Nat192.create();
        SecP192K1Field.subtract(U1, U2, H);
        SecP192K1Field.subtract(S1, S2, t2);
        if (!Nat192.isZero(H)) {
            SecP192K1Field.square(H, t3);
            int[] G = Nat192.create();
            SecP192K1Field.multiply(t3, H, G);
            SecP192K1Field.multiply(t3, U1, t3);
            SecP192K1Field.negate(G, G);
            Nat192.mul(S1, G, tt1);
            SecP192K1Field.reduce32(Nat192.addBothTo(t3, t3, G), G);
            SecP192K1FieldElement X3 = new SecP192K1FieldElement(t4);
            SecP192K1Field.square(t2, X3.x);
            SecP192K1Field.subtract(X3.x, G, X3.x);
            SecP192K1FieldElement Y3 = new SecP192K1FieldElement(G);
            SecP192K1Field.subtract(t3, X3.x, Y3.x);
            SecP192K1Field.multiplyAddToExt(Y3.x, t2, tt1);
            SecP192K1Field.reduce(tt1, Y3.x);
            SecP192K1FieldElement Z3 = new SecP192K1FieldElement(H);
            if (!Z1IsOne) {
                SecP192K1Field.multiply(Z3.x, Z1.x, Z3.x);
            }
            if (!Z2IsOne) {
                SecP192K1Field.multiply(Z3.x, Z2.x, Z3.x);
            }
            return new SecP192K1Point(curve, X3, Y3, new ECFieldElement[]{Z3});
        } else if (Nat192.isZero(t2)) {
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
        SecP192K1FieldElement Y1 = (SecP192K1FieldElement) this.y;
        if (Y1.isZero()) {
            return curve.getInfinity();
        }
        SecP192K1FieldElement X1 = (SecP192K1FieldElement) this.x;
        SecP192K1FieldElement Z1 = (SecP192K1FieldElement) this.zs[0];
        int[] Y1Squared = Nat192.create();
        SecP192K1Field.square(Y1.x, Y1Squared);
        int[] T = Nat192.create();
        SecP192K1Field.square(Y1Squared, T);
        int[] M = Nat192.create();
        SecP192K1Field.square(X1.x, M);
        SecP192K1Field.reduce32(Nat192.addBothTo(M, M, M), M);
        SecP192K1Field.multiply(Y1Squared, X1.x, Y1Squared);
        SecP192K1Field.reduce32(Nat.shiftUpBits(6, Y1Squared, 2, 0), Y1Squared);
        int[] t1 = Nat192.create();
        SecP192K1Field.reduce32(Nat.shiftUpBits(6, T, 3, 0, t1), t1);
        SecP192K1FieldElement X3 = new SecP192K1FieldElement(T);
        SecP192K1Field.square(M, X3.x);
        SecP192K1Field.subtract(X3.x, Y1Squared, X3.x);
        SecP192K1Field.subtract(X3.x, Y1Squared, X3.x);
        SecP192K1FieldElement Y3 = new SecP192K1FieldElement(Y1Squared);
        SecP192K1Field.subtract(Y1Squared, X3.x, Y3.x);
        SecP192K1Field.multiply(Y3.x, M, Y3.x);
        SecP192K1Field.subtract(Y3.x, t1, Y3.x);
        SecP192K1FieldElement Z3 = new SecP192K1FieldElement(M);
        SecP192K1Field.twice(Y1.x, Z3.x);
        if (!Z1.isOne()) {
            SecP192K1Field.multiply(Z3.x, Z1.x, Z3.x);
        }
        return new SecP192K1Point(curve, X3, Y3, new ECFieldElement[]{Z3});
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
        return isInfinity() ? this : new SecP192K1Point(this.curve, this.x, this.y.negate(), this.zs);
    }
}
