package com.mi.car.jsse.easysec.math.ec.custom.djb;

import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.raw.Nat256;

public class Curve25519Point extends ECPoint.AbstractFp {
    Curve25519Point(ECCurve curve, ECFieldElement x, ECFieldElement y) {
        super(curve, x, y);
    }

    Curve25519Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        super(curve, x, y, zs);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint detach() {
        return new Curve25519Point(null, getAffineXCoord(), getAffineYCoord());
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECFieldElement getZCoord(int index) {
        if (index == 1) {
            return getJacobianModifiedW();
        }
        return super.getZCoord(index);
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
        Curve25519FieldElement X1 = (Curve25519FieldElement) this.x;
        Curve25519FieldElement Y1 = (Curve25519FieldElement) this.y;
        Curve25519FieldElement Z1 = (Curve25519FieldElement) this.zs[0];
        Curve25519FieldElement X2 = (Curve25519FieldElement) b.getXCoord();
        Curve25519FieldElement Y2 = (Curve25519FieldElement) b.getYCoord();
        Curve25519FieldElement Z2 = (Curve25519FieldElement) b.getZCoord(0);
        int[] tt1 = Nat256.createExt();
        int[] t2 = Nat256.create();
        int[] t3 = Nat256.create();
        int[] t4 = Nat256.create();
        boolean Z1IsOne = Z1.isOne();
        if (Z1IsOne) {
            U2 = X2.x;
            S2 = Y2.x;
        } else {
            S2 = t3;
            Curve25519Field.square(Z1.x, S2);
            U2 = t2;
            Curve25519Field.multiply(S2, X2.x, U2);
            Curve25519Field.multiply(S2, Z1.x, S2);
            Curve25519Field.multiply(S2, Y2.x, S2);
        }
        boolean Z2IsOne = Z2.isOne();
        if (Z2IsOne) {
            U1 = X1.x;
            S1 = Y1.x;
        } else {
            S1 = t4;
            Curve25519Field.square(Z2.x, S1);
            U1 = tt1;
            Curve25519Field.multiply(S1, X1.x, U1);
            Curve25519Field.multiply(S1, Z2.x, S1);
            Curve25519Field.multiply(S1, Y1.x, S1);
        }
        int[] H = Nat256.create();
        Curve25519Field.subtract(U1, U2, H);
        Curve25519Field.subtract(S1, S2, t2);
        if (!Nat256.isZero(H)) {
            int[] HSquared = Nat256.create();
            Curve25519Field.square(H, HSquared);
            int[] G = Nat256.create();
            Curve25519Field.multiply(HSquared, H, G);
            Curve25519Field.multiply(HSquared, U1, t3);
            Curve25519Field.negate(G, G);
            Nat256.mul(S1, G, tt1);
            Curve25519Field.reduce27(Nat256.addBothTo(t3, t3, G), G);
            Curve25519FieldElement X3 = new Curve25519FieldElement(t4);
            Curve25519Field.square(t2, X3.x);
            Curve25519Field.subtract(X3.x, G, X3.x);
            Curve25519FieldElement Y3 = new Curve25519FieldElement(G);
            Curve25519Field.subtract(t3, X3.x, Y3.x);
            Curve25519Field.multiplyAddToExt(Y3.x, t2, tt1);
            Curve25519Field.reduce(tt1, Y3.x);
            Curve25519FieldElement Z3 = new Curve25519FieldElement(H);
            if (!Z1IsOne) {
                Curve25519Field.multiply(Z3.x, Z1.x, Z3.x);
            }
            if (!Z2IsOne) {
                Curve25519Field.multiply(Z3.x, Z2.x, Z3.x);
            }
            return new Curve25519Point(curve, X3, Y3, new ECFieldElement[]{Z3, calculateJacobianModifiedW(Z3, (!Z1IsOne || !Z2IsOne) ? null : HSquared)});
        } else if (Nat256.isZero(t2)) {
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
        if (this.y.isZero()) {
            return curve.getInfinity();
        }
        return twiceJacobianModified(true);
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
        return !this.y.isZero() ? twiceJacobianModified(false).add(b) : b;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint threeTimes() {
        return (!isInfinity() && !this.y.isZero()) ? twiceJacobianModified(false).add(this) : this;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint negate() {
        return isInfinity() ? this : new Curve25519Point(getCurve(), this.x, this.y.negate(), this.zs);
    }

    /* access modifiers changed from: protected */
    public Curve25519FieldElement calculateJacobianModifiedW(Curve25519FieldElement Z, int[] ZSquared) {
        Curve25519FieldElement a4 = (Curve25519FieldElement) getCurve().getA();
        if (Z.isOne()) {
            return a4;
        }
        Curve25519FieldElement W = new Curve25519FieldElement();
        if (ZSquared == null) {
            ZSquared = W.x;
            Curve25519Field.square(Z.x, ZSquared);
        }
        Curve25519Field.square(ZSquared, W.x);
        Curve25519Field.multiply(W.x, a4.x, W.x);
        return W;
    }

    /* access modifiers changed from: protected */
    public Curve25519FieldElement getJacobianModifiedW() {
        Curve25519FieldElement W = (Curve25519FieldElement) this.zs[1];
        if (W != null) {
            return W;
        }
        ECFieldElement[] eCFieldElementArr = this.zs;
        Curve25519FieldElement W2 = calculateJacobianModifiedW((Curve25519FieldElement) this.zs[0], null);
        eCFieldElementArr[1] = W2;
        return W2;
    }

    /* access modifiers changed from: protected */
    public Curve25519Point twiceJacobianModified(boolean calculateW) {
        Curve25519FieldElement X1 = (Curve25519FieldElement) this.x;
        Curve25519FieldElement Y1 = (Curve25519FieldElement) this.y;
        Curve25519FieldElement Z1 = (Curve25519FieldElement) this.zs[0];
        Curve25519FieldElement W1 = getJacobianModifiedW();
        int[] M = Nat256.create();
        Curve25519Field.square(X1.x, M);
        Curve25519Field.reduce27(Nat256.addBothTo(M, M, M) + Nat256.addTo(W1.x, M), M);
        int[] _2Y1 = Nat256.create();
        Curve25519Field.twice(Y1.x, _2Y1);
        int[] _2Y1Squared = Nat256.create();
        Curve25519Field.multiply(_2Y1, Y1.x, _2Y1Squared);
        int[] S = Nat256.create();
        Curve25519Field.multiply(_2Y1Squared, X1.x, S);
        Curve25519Field.twice(S, S);
        int[] _8T = Nat256.create();
        Curve25519Field.square(_2Y1Squared, _8T);
        Curve25519Field.twice(_8T, _8T);
        Curve25519FieldElement X3 = new Curve25519FieldElement(_2Y1Squared);
        Curve25519Field.square(M, X3.x);
        Curve25519Field.subtract(X3.x, S, X3.x);
        Curve25519Field.subtract(X3.x, S, X3.x);
        Curve25519FieldElement Y3 = new Curve25519FieldElement(S);
        Curve25519Field.subtract(S, X3.x, Y3.x);
        Curve25519Field.multiply(Y3.x, M, Y3.x);
        Curve25519Field.subtract(Y3.x, _8T, Y3.x);
        Curve25519FieldElement Z3 = new Curve25519FieldElement(_2Y1);
        if (!Nat256.isOne(Z1.x)) {
            Curve25519Field.multiply(Z3.x, Z1.x, Z3.x);
        }
        Curve25519FieldElement W3 = null;
        if (calculateW) {
            W3 = new Curve25519FieldElement(_8T);
            Curve25519Field.multiply(W3.x, W1.x, W3.x);
            Curve25519Field.twice(W3.x, W3.x);
        }
        return new Curve25519Point(getCurve(), X3, Y3, new ECFieldElement[]{Z3, W3});
    }
}
