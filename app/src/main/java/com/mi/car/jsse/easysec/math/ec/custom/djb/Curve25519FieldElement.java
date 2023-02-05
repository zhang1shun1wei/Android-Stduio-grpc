package com.mi.car.jsse.easysec.math.ec.custom.djb;

import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.raw.Nat256;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class Curve25519FieldElement extends ECFieldElement.AbstractFp {
    private static final int[] PRECOMP_POW2 = {1242472624, -991028441, -1389370248, 792926214, 1039914919, 726466713, 1338105611, 730014848};
    public static final BigInteger Q = Nat256.toBigInteger(Curve25519Field.P);
    protected int[] x;

    public Curve25519FieldElement(BigInteger x2) {
        if (x2 == null || x2.signum() < 0 || x2.compareTo(Q) >= 0) {
            throw new IllegalArgumentException("x value invalid for Curve25519FieldElement");
        }
        this.x = Curve25519Field.fromBigInteger(x2);
    }

    public Curve25519FieldElement() {
        this.x = Nat256.create();
    }

    protected Curve25519FieldElement(int[] x2) {
        this.x = x2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isZero() {
        return Nat256.isZero(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isOne() {
        return Nat256.isOne(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean testBitZero() {
        return Nat256.getBit(this.x, 0) == 1;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat256.toBigInteger(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public String getFieldName() {
        return "Curve25519Field";
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public int getFieldSize() {
        return Q.bitLength();
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement add(ECFieldElement b) {
        int[] z = Nat256.create();
        Curve25519Field.add(this.x, ((Curve25519FieldElement) b).x, z);
        return new Curve25519FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement addOne() {
        int[] z = Nat256.create();
        Curve25519Field.addOne(this.x, z);
        return new Curve25519FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement b) {
        int[] z = Nat256.create();
        Curve25519Field.subtract(this.x, ((Curve25519FieldElement) b).x, z);
        return new Curve25519FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement b) {
        int[] z = Nat256.create();
        Curve25519Field.multiply(this.x, ((Curve25519FieldElement) b).x, z);
        return new Curve25519FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement divide(ECFieldElement b) {
        int[] z = Nat256.create();
        Curve25519Field.inv(((Curve25519FieldElement) b).x, z);
        Curve25519Field.multiply(z, this.x, z);
        return new Curve25519FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement negate() {
        int[] z = Nat256.create();
        Curve25519Field.negate(this.x, z);
        return new Curve25519FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement square() {
        int[] z = Nat256.create();
        Curve25519Field.square(this.x, z);
        return new Curve25519FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement invert() {
        int[] z = Nat256.create();
        Curve25519Field.inv(this.x, z);
        return new Curve25519FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement sqrt() {
        int[] x1 = this.x;
        if (Nat256.isZero(x1) || Nat256.isOne(x1)) {
            return this;
        }
        int[] x2 = Nat256.create();
        Curve25519Field.square(x1, x2);
        Curve25519Field.multiply(x2, x1, x2);
        Curve25519Field.square(x2, x2);
        Curve25519Field.multiply(x2, x1, x2);
        int[] x4 = Nat256.create();
        Curve25519Field.square(x2, x4);
        Curve25519Field.multiply(x4, x1, x4);
        int[] x7 = Nat256.create();
        Curve25519Field.squareN(x4, 3, x7);
        Curve25519Field.multiply(x7, x2, x7);
        Curve25519Field.squareN(x7, 4, x2);
        Curve25519Field.multiply(x2, x4, x2);
        Curve25519Field.squareN(x2, 4, x7);
        Curve25519Field.multiply(x7, x4, x7);
        Curve25519Field.squareN(x7, 15, x4);
        Curve25519Field.multiply(x4, x7, x4);
        Curve25519Field.squareN(x4, 30, x7);
        Curve25519Field.multiply(x7, x4, x7);
        Curve25519Field.squareN(x7, 60, x4);
        Curve25519Field.multiply(x4, x7, x4);
        Curve25519Field.squareN(x4, 11, x7);
        Curve25519Field.multiply(x7, x2, x7);
        Curve25519Field.squareN(x7, 120, x2);
        Curve25519Field.multiply(x2, x4, x2);
        Curve25519Field.square(x2, x2);
        Curve25519Field.square(x2, x4);
        if (Nat256.eq(x1, x4)) {
            return new Curve25519FieldElement(x2);
        }
        Curve25519Field.multiply(x2, PRECOMP_POW2, x2);
        Curve25519Field.square(x2, x4);
        if (Nat256.eq(x1, x4)) {
            return new Curve25519FieldElement(x2);
        }
        return null;
    }

    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof Curve25519FieldElement)) {
            return false;
        }
        return Nat256.eq(this.x, ((Curve25519FieldElement) other).x);
    }

    public int hashCode() {
        return Q.hashCode() ^ Arrays.hashCode(this.x, 0, 8);
    }
}
