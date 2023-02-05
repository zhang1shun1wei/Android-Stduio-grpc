package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.raw.Nat128;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.math.BigInteger;

public class SecP128R1FieldElement extends ECFieldElement.AbstractFp {
    public static final BigInteger Q = new BigInteger(1, Hex.decodeStrict("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF"));
    protected int[] x;

    public SecP128R1FieldElement(BigInteger x2) {
        if (x2 == null || x2.signum() < 0 || x2.compareTo(Q) >= 0) {
            throw new IllegalArgumentException("x value invalid for SecP128R1FieldElement");
        }
        this.x = SecP128R1Field.fromBigInteger(x2);
    }

    public SecP128R1FieldElement() {
        this.x = Nat128.create();
    }

    protected SecP128R1FieldElement(int[] x2) {
        this.x = x2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isZero() {
        return Nat128.isZero(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isOne() {
        return Nat128.isOne(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean testBitZero() {
        return Nat128.getBit(this.x, 0) == 1;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat128.toBigInteger(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public String getFieldName() {
        return "SecP128R1Field";
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public int getFieldSize() {
        return Q.bitLength();
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement add(ECFieldElement b) {
        int[] z = Nat128.create();
        SecP128R1Field.add(this.x, ((SecP128R1FieldElement) b).x, z);
        return new SecP128R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement addOne() {
        int[] z = Nat128.create();
        SecP128R1Field.addOne(this.x, z);
        return new SecP128R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement b) {
        int[] z = Nat128.create();
        SecP128R1Field.subtract(this.x, ((SecP128R1FieldElement) b).x, z);
        return new SecP128R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement b) {
        int[] z = Nat128.create();
        SecP128R1Field.multiply(this.x, ((SecP128R1FieldElement) b).x, z);
        return new SecP128R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement divide(ECFieldElement b) {
        int[] z = Nat128.create();
        SecP128R1Field.inv(((SecP128R1FieldElement) b).x, z);
        SecP128R1Field.multiply(z, this.x, z);
        return new SecP128R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement negate() {
        int[] z = Nat128.create();
        SecP128R1Field.negate(this.x, z);
        return new SecP128R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement square() {
        int[] z = Nat128.create();
        SecP128R1Field.square(this.x, z);
        return new SecP128R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement invert() {
        int[] z = Nat128.create();
        SecP128R1Field.inv(this.x, z);
        return new SecP128R1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement sqrt() {
        int[] x1 = this.x;
        if (Nat128.isZero(x1) || Nat128.isOne(x1)) {
            return this;
        }
        int[] x2 = Nat128.create();
        SecP128R1Field.square(x1, x2);
        SecP128R1Field.multiply(x2, x1, x2);
        int[] x4 = Nat128.create();
        SecP128R1Field.squareN(x2, 2, x4);
        SecP128R1Field.multiply(x4, x2, x4);
        int[] x8 = Nat128.create();
        SecP128R1Field.squareN(x4, 4, x8);
        SecP128R1Field.multiply(x8, x4, x8);
        SecP128R1Field.squareN(x8, 2, x4);
        SecP128R1Field.multiply(x4, x2, x4);
        SecP128R1Field.squareN(x4, 10, x2);
        SecP128R1Field.multiply(x2, x4, x2);
        SecP128R1Field.squareN(x2, 10, x8);
        SecP128R1Field.multiply(x8, x4, x8);
        SecP128R1Field.square(x8, x4);
        SecP128R1Field.multiply(x4, x1, x4);
        SecP128R1Field.squareN(x4, 95, x4);
        SecP128R1Field.square(x4, x8);
        if (Nat128.eq(x1, x8)) {
            return new SecP128R1FieldElement(x4);
        }
        return null;
    }

    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof SecP128R1FieldElement)) {
            return false;
        }
        return Nat128.eq(this.x, ((SecP128R1FieldElement) other).x);
    }

    public int hashCode() {
        return Q.hashCode() ^ Arrays.hashCode(this.x, 0, 4);
    }
}
