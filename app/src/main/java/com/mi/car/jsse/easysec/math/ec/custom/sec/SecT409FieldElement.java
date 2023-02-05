package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat448;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class SecT409FieldElement extends ECFieldElement.AbstractF2m {
    protected long[] x;

    public SecT409FieldElement(BigInteger x2) {
        if (x2 == null || x2.signum() < 0 || x2.bitLength() > 409) {
            throw new IllegalArgumentException("x value invalid for SecT409FieldElement");
        }
        this.x = SecT409Field.fromBigInteger(x2);
    }

    public SecT409FieldElement() {
        this.x = Nat448.create64();
    }

    protected SecT409FieldElement(long[] x2) {
        this.x = x2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isOne() {
        return Nat448.isOne64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isZero() {
        return Nat448.isZero64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean testBitZero() {
        return (this.x[0] & 1) != 0;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat448.toBigInteger64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public String getFieldName() {
        return "SecT409Field";
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public int getFieldSize() {
        return 409;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement add(ECFieldElement b) {
        long[] z = Nat448.create64();
        SecT409Field.add(this.x, ((SecT409FieldElement) b).x, z);
        return new SecT409FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement addOne() {
        long[] z = Nat448.create64();
        SecT409Field.addOne(this.x, z);
        return new SecT409FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement b) {
        return add(b);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement b) {
        long[] z = Nat448.create64();
        SecT409Field.multiply(this.x, ((SecT409FieldElement) b).x, z);
        return new SecT409FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        return multiplyPlusProduct(b, x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] bx = ((SecT409FieldElement) b).x;
        long[] xx = ((SecT409FieldElement) x2).x;
        long[] yx = ((SecT409FieldElement) y).x;
        long[] tt = Nat.create64(13);
        SecT409Field.multiplyAddToExt(ax, bx, tt);
        SecT409Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat448.create64();
        SecT409Field.reduce(tt, z);
        return new SecT409FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement divide(ECFieldElement b) {
        return multiply(b.invert());
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement negate() {
        return this;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement square() {
        long[] z = Nat448.create64();
        SecT409Field.square(this.x, z);
        return new SecT409FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squareMinusProduct(ECFieldElement x2, ECFieldElement y) {
        return squarePlusProduct(x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePlusProduct(ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] xx = ((SecT409FieldElement) x2).x;
        long[] yx = ((SecT409FieldElement) y).x;
        long[] tt = Nat.create64(13);
        SecT409Field.squareAddToExt(ax, tt);
        SecT409Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat448.create64();
        SecT409Field.reduce(tt, z);
        return new SecT409FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePow(int pow) {
        if (pow < 1) {
            return this;
        }
        long[] z = Nat448.create64();
        SecT409Field.squareN(this.x, pow, z);
        return new SecT409FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public ECFieldElement halfTrace() {
        long[] z = Nat448.create64();
        SecT409Field.halfTrace(this.x, z);
        return new SecT409FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public boolean hasFastTrace() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public int trace() {
        return SecT409Field.trace(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement invert() {
        long[] z = Nat448.create64();
        SecT409Field.invert(this.x, z);
        return new SecT409FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement sqrt() {
        long[] z = Nat448.create64();
        SecT409Field.sqrt(this.x, z);
        return new SecT409FieldElement(z);
    }

    public int getRepresentation() {
        return 2;
    }

    public int getM() {
        return 409;
    }

    public int getK1() {
        return 87;
    }

    public int getK2() {
        return 0;
    }

    public int getK3() {
        return 0;
    }

    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof SecT409FieldElement)) {
            return false;
        }
        return Nat448.eq64(this.x, ((SecT409FieldElement) other).x);
    }

    public int hashCode() {
        return 4090087 ^ Arrays.hashCode(this.x, 0, 7);
    }
}
