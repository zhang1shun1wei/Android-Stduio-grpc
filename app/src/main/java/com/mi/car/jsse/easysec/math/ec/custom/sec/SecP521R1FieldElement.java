package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.math.BigInteger;

public class SecP521R1FieldElement extends ECFieldElement.AbstractFp {
    public static final BigInteger Q = new BigInteger(1, Hex.decodeStrict("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
    protected int[] x;

    public SecP521R1FieldElement(BigInteger x2) {
        if (x2 == null || x2.signum() < 0 || x2.compareTo(Q) >= 0) {
            throw new IllegalArgumentException("x value invalid for SecP521R1FieldElement");
        }
        this.x = SecP521R1Field.fromBigInteger(x2);
    }

    public SecP521R1FieldElement() {
        this.x = Nat.create(17);
    }

    protected SecP521R1FieldElement(int[] x2) {
        this.x = x2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isZero() {
        return Nat.isZero(17, this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isOne() {
        return Nat.isOne(17, this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean testBitZero() {
        return Nat.getBit(this.x, 0) == 1;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat.toBigInteger(17, this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public String getFieldName() {
        return "SecP521R1Field";
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public int getFieldSize() {
        return Q.bitLength();
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement add(ECFieldElement b) {
        int[] z = Nat.create(17);
        SecP521R1Field.add(this.x, ((SecP521R1FieldElement) b).x, z);
        return new SecP521R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement addOne() {
        int[] z = Nat.create(17);
        SecP521R1Field.addOne(this.x, z);
        return new SecP521R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement b) {
        int[] z = Nat.create(17);
        SecP521R1Field.subtract(this.x, ((SecP521R1FieldElement) b).x, z);
        return new SecP521R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement b) {
        int[] z = Nat.create(17);
        SecP521R1Field.multiply(this.x, ((SecP521R1FieldElement) b).x, z);
        return new SecP521R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement divide(ECFieldElement b) {
        int[] z = Nat.create(17);
        SecP521R1Field.inv(((SecP521R1FieldElement) b).x, z);
        SecP521R1Field.multiply(z, this.x, z);
        return new SecP521R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement negate() {
        int[] z = Nat.create(17);
        SecP521R1Field.negate(this.x, z);
        return new SecP521R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement square() {
        int[] z = Nat.create(17);
        SecP521R1Field.square(this.x, z);
        return new SecP521R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement invert() {
        int[] z = Nat.create(17);
        SecP521R1Field.inv(this.x, z);
        return new SecP521R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement sqrt() {
        int[] x1 = this.x;
        if (Nat.isZero(17, x1) || Nat.isOne(17, x1)) {
            return this;
        }
        int[] tt0 = Nat.create(33);
        int[] t1 = Nat.create(17);
        int[] t2 = Nat.create(17);
        SecP521R1Field.squareN(x1, 519, t1, tt0);
        SecP521R1Field.square(t1, t2, tt0);
        if (Nat.eq(17, x1, t2)) {
            return new SecP521R1FieldElement(t1);
        }
        return null;
    }

    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof SecP521R1FieldElement)) {
            return false;
        }
        return Nat.eq(17, this.x, ((SecP521R1FieldElement) other).x);
    }

    public int hashCode() {
        return Q.hashCode() ^ Arrays.hashCode(this.x, 0, 17);
    }
}
