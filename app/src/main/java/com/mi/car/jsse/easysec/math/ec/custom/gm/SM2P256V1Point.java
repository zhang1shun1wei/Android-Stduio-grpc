package com.mi.car.jsse.easysec.math.ec.custom.gm;

import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat256;

public class SM2P256V1Point extends ECPoint.AbstractFp {
    SM2P256V1Point(ECCurve curve, ECFieldElement x, ECFieldElement y) {
        super(curve, x, y);
    }

    SM2P256V1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
        super(curve, x, y, zs);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.math.ec.ECPoint
    public ECPoint detach() {
        return new SM2P256V1Point(null, getAffineXCoord(), getAffineYCoord());
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
        SM2P256V1FieldElement X1 = (SM2P256V1FieldElement) this.x;
        SM2P256V1FieldElement Y1 = (SM2P256V1FieldElement) this.y;
        SM2P256V1FieldElement X2 = (SM2P256V1FieldElement) b.getXCoord();
        SM2P256V1FieldElement Y2 = (SM2P256V1FieldElement) b.getYCoord();
        SM2P256V1FieldElement Z1 = (SM2P256V1FieldElement) this.zs[0];
        SM2P256V1FieldElement Z2 = (SM2P256V1FieldElement) b.getZCoord(0);
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
            SM2P256V1Field.square(Z1.x, S2);
            U2 = t2;
            SM2P256V1Field.multiply(S2, X2.x, U2);
            SM2P256V1Field.multiply(S2, Z1.x, S2);
            SM2P256V1Field.multiply(S2, Y2.x, S2);
        }
        boolean Z2IsOne = Z2.isOne();
        if (Z2IsOne) {
            U1 = X1.x;
            S1 = Y1.x;
        } else {
            S1 = t4;
            SM2P256V1Field.square(Z2.x, S1);
            U1 = tt1;
            SM2P256V1Field.multiply(S1, X1.x, U1);
            SM2P256V1Field.multiply(S1, Z2.x, S1);
            SM2P256V1Field.multiply(S1, Y1.x, S1);
        }
        int[] H = Nat256.create();
        SM2P256V1Field.subtract(U1, U2, H);
        SM2P256V1Field.subtract(S1, S2, t2);
        if (!Nat256.isZero(H)) {
            SM2P256V1Field.square(H, t3);
            int[] G = Nat256.create();
            SM2P256V1Field.multiply(t3, H, G);
            SM2P256V1Field.multiply(t3, U1, t3);
            SM2P256V1Field.negate(G, G);
            Nat256.mul(S1, G, tt1);
            SM2P256V1Field.reduce32(Nat256.addBothTo(t3, t3, G), G);
            SM2P256V1FieldElement X3 = new SM2P256V1FieldElement(t4);
            SM2P256V1Field.square(t2, X3.x);
            SM2P256V1Field.subtract(X3.x, G, X3.x);
            SM2P256V1FieldElement Y3 = new SM2P256V1FieldElement(G);
            SM2P256V1Field.subtract(t3, X3.x, Y3.x);
            SM2P256V1Field.multiplyAddToExt(Y3.x, t2, tt1);
            SM2P256V1Field.reduce(tt1, Y3.x);
            SM2P256V1FieldElement Z3 = new SM2P256V1FieldElement(H);
            if (!Z1IsOne) {
                SM2P256V1Field.multiply(Z3.x, Z1.x, Z3.x);
            }
            if (!Z2IsOne) {
                SM2P256V1Field.multiply(Z3.x, Z2.x, Z3.x);
            }
            return new SM2P256V1Point(curve, X3, Y3, new ECFieldElement[]{Z3});
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
        SM2P256V1FieldElement Y1 = (SM2P256V1FieldElement) this.y;
        if (Y1.isZero()) {
            return curve.getInfinity();
        }
        SM2P256V1FieldElement X1 = (SM2P256V1FieldElement) this.x;
        SM2P256V1FieldElement Z1 = (SM2P256V1FieldElement) this.zs[0];
        int[] t1 = Nat256.create();
        int[] t2 = Nat256.create();
        int[] Y1Squared = Nat256.create();
        SM2P256V1Field.square(Y1.x, Y1Squared);
        int[] T = Nat256.create();
        SM2P256V1Field.square(Y1Squared, T);
        boolean Z1IsOne = Z1.isOne();
        int[] Z1Squared = Z1.x;
        if (!Z1IsOne) {
            Z1Squared = t2;
            SM2P256V1Field.square(Z1.x, Z1Squared);
        }
        SM2P256V1Field.subtract(X1.x, Z1Squared, t1);
        SM2P256V1Field.add(X1.x, Z1Squared, t2);
        SM2P256V1Field.multiply(t2, t1, t2);
        SM2P256V1Field.reduce32(Nat256.addBothTo(t2, t2, t2), t2);
        SM2P256V1Field.multiply(Y1Squared, X1.x, Y1Squared);
        SM2P256V1Field.reduce32(Nat.shiftUpBits(8, Y1Squared, 2, 0), Y1Squared);
        SM2P256V1Field.reduce32(Nat.shiftUpBits(8, T, 3, 0, t1), t1);
        SM2P256V1FieldElement X3 = new SM2P256V1FieldElement(T);
        SM2P256V1Field.square(t2, X3.x);
        SM2P256V1Field.subtract(X3.x, Y1Squared, X3.x);
        SM2P256V1Field.subtract(X3.x, Y1Squared, X3.x);
        SM2P256V1FieldElement Y3 = new SM2P256V1FieldElement(Y1Squared);
        SM2P256V1Field.subtract(Y1Squared, X3.x, Y3.x);
        SM2P256V1Field.multiply(Y3.x, t2, Y3.x);
        SM2P256V1Field.subtract(Y3.x, t1, Y3.x);
        SM2P256V1FieldElement Z3 = new SM2P256V1FieldElement(t2);
        SM2P256V1Field.twice(Y1.x, Z3.x);
        if (!Z1IsOne) {
            SM2P256V1Field.multiply(Z3.x, Z1.x, Z3.x);
        }
        return new SM2P256V1Point(curve, X3, Y3, new ECFieldElement[]{Z3});
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
        return isInfinity() ? this : new SM2P256V1Point(this.curve, this.x, this.y.negate(), this.zs);
    }
}
