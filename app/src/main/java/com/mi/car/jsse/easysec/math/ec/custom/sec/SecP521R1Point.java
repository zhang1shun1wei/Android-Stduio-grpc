package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.raw.Nat;

public class SecP521R1Point extends ECPoint.AbstractFp {
    SecP521R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y) {
        super(curve, x, y);
    }

    SecP521R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        super(curve, x, y, zs);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint detach() {
        return new SecP521R1Point(null, getAffineXCoord(), getAffineYCoord());
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
        SecP521R1FieldElement X1 = (SecP521R1FieldElement) this.x;
        SecP521R1FieldElement Y1 = (SecP521R1FieldElement) this.y;
        SecP521R1FieldElement X2 = (SecP521R1FieldElement) b.getXCoord();
        SecP521R1FieldElement Y2 = (SecP521R1FieldElement) b.getYCoord();
        SecP521R1FieldElement Z1 = (SecP521R1FieldElement) this.zs[0];
        SecP521R1FieldElement Z2 = (SecP521R1FieldElement) b.getZCoord(0);
        int[] tt0 = Nat.create(33);
        int[] t1 = Nat.create(17);
        int[] t2 = Nat.create(17);
        int[] t3 = Nat.create(17);
        int[] t4 = Nat.create(17);
        boolean Z1IsOne = Z1.isOne();
        if (Z1IsOne) {
            U2 = X2.x;
            S2 = Y2.x;
        } else {
            S2 = t3;
            SecP521R1Field.square(Z1.x, S2, tt0);
            U2 = t2;
            SecP521R1Field.multiply(S2, X2.x, U2, tt0);
            SecP521R1Field.multiply(S2, Z1.x, S2, tt0);
            SecP521R1Field.multiply(S2, Y2.x, S2, tt0);
        }
        boolean Z2IsOne = Z2.isOne();
        if (Z2IsOne) {
            U1 = X1.x;
            S1 = Y1.x;
        } else {
            S1 = t4;
            SecP521R1Field.square(Z2.x, S1, tt0);
            U1 = t1;
            SecP521R1Field.multiply(S1, X1.x, U1, tt0);
            SecP521R1Field.multiply(S1, Z2.x, S1, tt0);
            SecP521R1Field.multiply(S1, Y1.x, S1, tt0);
        }
        int[] H = Nat.create(17);
        SecP521R1Field.subtract(U1, U2, H);
        SecP521R1Field.subtract(S1, S2, t2);
        if (!Nat.isZero(17, H)) {
            SecP521R1Field.square(H, t3, tt0);
            int[] G = Nat.create(17);
            SecP521R1Field.multiply(t3, H, G, tt0);
            SecP521R1Field.multiply(t3, U1, t3, tt0);
            SecP521R1Field.multiply(S1, G, t1, tt0);
            SecP521R1FieldElement X3 = new SecP521R1FieldElement(t4);
            SecP521R1Field.square(t2, X3.x, tt0);
            SecP521R1Field.add(X3.x, G, X3.x);
            SecP521R1Field.subtract(X3.x, t3, X3.x);
            SecP521R1Field.subtract(X3.x, t3, X3.x);
            SecP521R1FieldElement Y3 = new SecP521R1FieldElement(G);
            SecP521R1Field.subtract(t3, X3.x, Y3.x);
            SecP521R1Field.multiply(Y3.x, t2, t2, tt0);
            SecP521R1Field.subtract(t2, t1, Y3.x);
            SecP521R1FieldElement Z3 = new SecP521R1FieldElement(H);
            if (!Z1IsOne) {
                SecP521R1Field.multiply(Z3.x, Z1.x, Z3.x, tt0);
            }
            if (!Z2IsOne) {
                SecP521R1Field.multiply(Z3.x, Z2.x, Z3.x, tt0);
            }
            return new SecP521R1Point(curve, X3, Y3, new ECFieldElement[]{Z3});
        } else if (Nat.isZero(17, t2)) {
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
        SecP521R1FieldElement Y1 = (SecP521R1FieldElement) this.y;
        if (Y1.isZero()) {
            return curve.getInfinity();
        }
        SecP521R1FieldElement X1 = (SecP521R1FieldElement) this.x;
        SecP521R1FieldElement Z1 = (SecP521R1FieldElement) this.zs[0];
        int[] tt0 = Nat.create(33);
        int[] t1 = Nat.create(17);
        int[] t2 = Nat.create(17);
        int[] Y1Squared = Nat.create(17);
        SecP521R1Field.square(Y1.x, Y1Squared, tt0);
        int[] T = Nat.create(17);
        SecP521R1Field.square(Y1Squared, T, tt0);
        boolean Z1IsOne = Z1.isOne();
        int[] Z1Squared = Z1.x;
        if (!Z1IsOne) {
            Z1Squared = t2;
            SecP521R1Field.square(Z1.x, Z1Squared, tt0);
        }
        SecP521R1Field.subtract(X1.x, Z1Squared, t1);
        SecP521R1Field.add(X1.x, Z1Squared, t2);
        SecP521R1Field.multiply(t2, t1, t2, tt0);
        Nat.addBothTo(17, t2, t2, t2);
        SecP521R1Field.reduce23(t2);
        SecP521R1Field.multiply(Y1Squared, X1.x, Y1Squared, tt0);
        Nat.shiftUpBits(17, Y1Squared, 2, 0);
        SecP521R1Field.reduce23(Y1Squared);
        Nat.shiftUpBits(17, T, 3, 0, t1);
        SecP521R1Field.reduce23(t1);
        SecP521R1FieldElement X3 = new SecP521R1FieldElement(T);
        SecP521R1Field.square(t2, X3.x, tt0);
        SecP521R1Field.subtract(X3.x, Y1Squared, X3.x);
        SecP521R1Field.subtract(X3.x, Y1Squared, X3.x);
        SecP521R1FieldElement Y3 = new SecP521R1FieldElement(Y1Squared);
        SecP521R1Field.subtract(Y1Squared, X3.x, Y3.x);
        SecP521R1Field.multiply(Y3.x, t2, Y3.x, tt0);
        SecP521R1Field.subtract(Y3.x, t1, Y3.x);
        SecP521R1FieldElement Z3 = new SecP521R1FieldElement(t2);
        SecP521R1Field.twice(Y1.x, Z3.x);
        if (!Z1IsOne) {
            SecP521R1Field.multiply(Z3.x, Z1.x, Z3.x, tt0);
        }
        return new SecP521R1Point(curve, X3, Y3, new ECFieldElement[]{Z3});
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

    /* access modifiers changed from: protected */
    public ECFieldElement two(ECFieldElement x) {
        return x.add(x);
    }

    /* access modifiers changed from: protected */
    public ECFieldElement three(ECFieldElement x) {
        return two(x).add(x);
    }

    /* access modifiers changed from: protected */
    public ECFieldElement four(ECFieldElement x) {
        return two(two(x));
    }

    /* access modifiers changed from: protected */
    public ECFieldElement eight(ECFieldElement x) {
        return four(two(x));
    }

    /* access modifiers changed from: protected */
    public ECFieldElement doubleProductFromSquares(ECFieldElement a, ECFieldElement b, ECFieldElement aSquared, ECFieldElement bSquared) {
        return a.add(b).square().subtract(aSquared).subtract(bSquared);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint negate() {
        return isInfinity() ? this : new SecP521R1Point(this.curve, this.x, this.y.negate(), this.zs);
    }
}
