package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.raw.Nat160;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.math.BigInteger;

public class SecP160R2FieldElement extends ECFieldElement.AbstractFp {
    public static final BigInteger Q = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73"));
    protected int[] x;

    public SecP160R2FieldElement(BigInteger x2) {
        if (x2 == null || x2.signum() < 0 || x2.compareTo(Q) >= 0) {
            throw new IllegalArgumentException("x value invalid for SecP160R2FieldElement");
        }
        this.x = SecP160R2Field.fromBigInteger(x2);
    }

    public SecP160R2FieldElement() {
        this.x = Nat160.create();
    }

    protected SecP160R2FieldElement(int[] x2) {
        this.x = x2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isZero() {
        return Nat160.isZero(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isOne() {
        return Nat160.isOne(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean testBitZero() {
        return Nat160.getBit(this.x, 0) == 1;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat160.toBigInteger(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public String getFieldName() {
        return "SecP160R2Field";
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public int getFieldSize() {
        return Q.bitLength();
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement add(ECFieldElement b) {
        int[] z = Nat160.create();
        SecP160R2Field.add(this.x, ((SecP160R2FieldElement) b).x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement addOne() {
        int[] z = Nat160.create();
        SecP160R2Field.addOne(this.x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement b) {
        int[] z = Nat160.create();
        SecP160R2Field.subtract(this.x, ((SecP160R2FieldElement) b).x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement b) {
        int[] z = Nat160.create();
        SecP160R2Field.multiply(this.x, ((SecP160R2FieldElement) b).x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement divide(ECFieldElement b) {
        int[] z = Nat160.create();
        SecP160R2Field.inv(((SecP160R2FieldElement) b).x, z);
        SecP160R2Field.multiply(z, this.x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement negate() {
        int[] z = Nat160.create();
        SecP160R2Field.negate(this.x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement square() {
        int[] z = Nat160.create();
        SecP160R2Field.square(this.x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement invert() {
        int[] z = Nat160.create();
        SecP160R2Field.inv(this.x, z);
        return new SecP160R2FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement sqrt() {
        int[] x1 = this.x;
        if (Nat160.isZero(x1) || Nat160.isOne(x1)) {
            return this;
        }
        int[] x2 = Nat160.create();
        SecP160R2Field.square(x1, x2);
        SecP160R2Field.multiply(x2, x1, x2);
        int[] x3 = Nat160.create();
        SecP160R2Field.square(x2, x3);
        SecP160R2Field.multiply(x3, x1, x3);
        int[] x4 = Nat160.create();
        SecP160R2Field.square(x3, x4);
        SecP160R2Field.multiply(x4, x1, x4);
        int[] x7 = Nat160.create();
        SecP160R2Field.squareN(x4, 3, x7);
        SecP160R2Field.multiply(x7, x3, x7);
        SecP160R2Field.squareN(x7, 7, x4);
        SecP160R2Field.multiply(x4, x7, x4);
        SecP160R2Field.squareN(x4, 3, x7);
        SecP160R2Field.multiply(x7, x3, x7);
        int[] x31 = Nat160.create();
        SecP160R2Field.squareN(x7, 14, x31);
        SecP160R2Field.multiply(x31, x4, x31);
        SecP160R2Field.squareN(x31, 31, x4);
        SecP160R2Field.multiply(x4, x31, x4);
        SecP160R2Field.squareN(x4, 62, x31);
        SecP160R2Field.multiply(x31, x4, x31);
        SecP160R2Field.squareN(x31, 3, x4);
        SecP160R2Field.multiply(x4, x3, x4);
        SecP160R2Field.squareN(x4, 18, x4);
        SecP160R2Field.multiply(x4, x7, x4);
        SecP160R2Field.squareN(x4, 2, x4);
        SecP160R2Field.multiply(x4, x1, x4);
        SecP160R2Field.squareN(x4, 3, x4);
        SecP160R2Field.multiply(x4, x2, x4);
        SecP160R2Field.squareN(x4, 6, x4);
        SecP160R2Field.multiply(x4, x3, x4);
        SecP160R2Field.squareN(x4, 2, x4);
        SecP160R2Field.multiply(x4, x1, x4);
        SecP160R2Field.square(x4, x2);
        if (Nat160.eq(x1, x2)) {
            return new SecP160R2FieldElement(x4);
        }
        return null;
    }

    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof SecP160R2FieldElement)) {
            return false;
        }
        return Nat160.eq(this.x, ((SecP160R2FieldElement) other).x);
    }

    public int hashCode() {
        return Q.hashCode() ^ Arrays.hashCode(this.x, 0, 5);
    }
}
