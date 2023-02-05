package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat384;

public class SecP384R1Point extends ECPoint.AbstractFp {
    SecP384R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y) {
        super(curve, x, y);
    }

    SecP384R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        super(curve, x, y, zs);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint detach() {
        return new SecP384R1Point(null, getAffineXCoord(), getAffineYCoord());
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
        SecP384R1FieldElement X1 = (SecP384R1FieldElement) this.x;
        SecP384R1FieldElement Y1 = (SecP384R1FieldElement) this.y;
        SecP384R1FieldElement X2 = (SecP384R1FieldElement) b.getXCoord();
        SecP384R1FieldElement Y2 = (SecP384R1FieldElement) b.getYCoord();
        SecP384R1FieldElement Z1 = (SecP384R1FieldElement) this.zs[0];
        SecP384R1FieldElement Z2 = (SecP384R1FieldElement) b.getZCoord(0);
        int[] tt0 = Nat.create(24);
        int[] tt1 = Nat.create(24);
        int[] tt2 = Nat.create(24);
        int[] t3 = Nat.create(12);
        int[] t4 = Nat.create(12);
        boolean Z1IsOne = Z1.isOne();
        if (Z1IsOne) {
            U2 = X2.x;
            S2 = Y2.x;
        } else {
            S2 = t3;
            SecP384R1Field.square(Z1.x, S2, tt0);
            U2 = tt2;
            SecP384R1Field.multiply(S2, X2.x, U2, tt0);
            SecP384R1Field.multiply(S2, Z1.x, S2, tt0);
            SecP384R1Field.multiply(S2, Y2.x, S2, tt0);
        }
        boolean Z2IsOne = Z2.isOne();
        if (Z2IsOne) {
            U1 = X1.x;
            S1 = Y1.x;
        } else {
            S1 = t4;
            SecP384R1Field.square(Z2.x, S1, tt0);
            U1 = tt1;
            SecP384R1Field.multiply(S1, X1.x, U1, tt0);
            SecP384R1Field.multiply(S1, Z2.x, S1, tt0);
            SecP384R1Field.multiply(S1, Y1.x, S1, tt0);
        }
        int[] H = Nat.create(12);
        SecP384R1Field.subtract(U1, U2, H);
        int[] R = Nat.create(12);
        SecP384R1Field.subtract(S1, S2, R);
        if (!Nat.isZero(12, H)) {
            SecP384R1Field.square(H, t3, tt0);
            int[] G = Nat.create(12);
            SecP384R1Field.multiply(t3, H, G, tt0);
            SecP384R1Field.multiply(t3, U1, t3, tt0);
            SecP384R1Field.negate(G, G);
            Nat384.mul(S1, G, tt1);
            SecP384R1Field.reduce32(Nat.addBothTo(12, t3, t3, G), G);
            SecP384R1FieldElement X3 = new SecP384R1FieldElement(t4);
            SecP384R1Field.square(R, X3.x, tt0);
            SecP384R1Field.subtract(X3.x, G, X3.x);
            SecP384R1FieldElement Y3 = new SecP384R1FieldElement(G);
            SecP384R1Field.subtract(t3, X3.x, Y3.x);
            Nat384.mul(Y3.x, R, tt2);
            SecP384R1Field.addExt(tt1, tt2, tt1);
            SecP384R1Field.reduce(tt1, Y3.x);
            SecP384R1FieldElement Z3 = new SecP384R1FieldElement(H);
            if (!Z1IsOne) {
                SecP384R1Field.multiply(Z3.x, Z1.x, Z3.x, tt0);
            }
            if (!Z2IsOne) {
                SecP384R1Field.multiply(Z3.x, Z2.x, Z3.x, tt0);
            }
            return new SecP384R1Point(curve, X3, Y3, new ECFieldElement[]{Z3});
        } else if (Nat.isZero(12, R)) {
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
        SecP384R1FieldElement Y1 = (SecP384R1FieldElement) this.y;
        if (Y1.isZero()) {
            return curve.getInfinity();
        }
        SecP384R1FieldElement X1 = (SecP384R1FieldElement) this.x;
        SecP384R1FieldElement Z1 = (SecP384R1FieldElement) this.zs[0];
        int[] tt0 = Nat.create(24);
        int[] t1 = Nat.create(12);
        int[] t2 = Nat.create(12);
        int[] Y1Squared = Nat.create(12);
        SecP384R1Field.square(Y1.x, Y1Squared, tt0);
        int[] T = Nat.create(12);
        SecP384R1Field.square(Y1Squared, T, tt0);
        boolean Z1IsOne = Z1.isOne();
        int[] Z1Squared = Z1.x;
        if (!Z1IsOne) {
            Z1Squared = t2;
            SecP384R1Field.square(Z1.x, Z1Squared, tt0);
        }
        SecP384R1Field.subtract(X1.x, Z1Squared, t1);
        SecP384R1Field.add(X1.x, Z1Squared, t2);
        SecP384R1Field.multiply(t2, t1, t2, tt0);
        SecP384R1Field.reduce32(Nat.addBothTo(12, t2, t2, t2), t2);
        SecP384R1Field.multiply(Y1Squared, X1.x, Y1Squared, tt0);
        SecP384R1Field.reduce32(Nat.shiftUpBits(12, Y1Squared, 2, 0), Y1Squared);
        SecP384R1Field.reduce32(Nat.shiftUpBits(12, T, 3, 0, t1), t1);
        SecP384R1FieldElement X3 = new SecP384R1FieldElement(T);
        SecP384R1Field.square(t2, X3.x, tt0);
        SecP384R1Field.subtract(X3.x, Y1Squared, X3.x);
        SecP384R1Field.subtract(X3.x, Y1Squared, X3.x);
        SecP384R1FieldElement Y3 = new SecP384R1FieldElement(Y1Squared);
        SecP384R1Field.subtract(Y1Squared, X3.x, Y3.x);
        SecP384R1Field.multiply(Y3.x, t2, Y3.x, tt0);
        SecP384R1Field.subtract(Y3.x, t1, Y3.x);
        SecP384R1FieldElement Z3 = new SecP384R1FieldElement(t2);
        SecP384R1Field.twice(Y1.x, Z3.x);
        if (!Z1IsOne) {
            SecP384R1Field.multiply(Z3.x, Z1.x, Z3.x, tt0);
        }
        return new SecP384R1Point(curve, X3, Y3, new ECFieldElement[]{Z3});
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
        return isInfinity() ? this : new SecP384R1Point(this.curve, this.x, this.y.negate(), this.zs);
    }
}
