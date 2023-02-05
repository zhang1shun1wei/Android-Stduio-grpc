package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.raw.Nat;
import com.mi.car.jsse.easysec.math.raw.Nat320;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class SecT283FieldElement extends ECFieldElement.AbstractF2m {
    protected long[] x;

    public SecT283FieldElement(BigInteger x2) {
        if (x2 == null || x2.signum() < 0 || x2.bitLength() > 283) {
            throw new IllegalArgumentException("x value invalid for SecT283FieldElement");
        }
        this.x = SecT283Field.fromBigInteger(x2);
    }

    public SecT283FieldElement() {
        this.x = Nat320.create64();
    }

    protected SecT283FieldElement(long[] x2) {
        this.x = x2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isOne() {
        return Nat320.isOne64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isZero() {
        return Nat320.isZero64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean testBitZero() {
        return (this.x[0] & 1) != 0;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat320.toBigInteger64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public String getFieldName() {
        return "SecT283Field";
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public int getFieldSize() {
        return 283;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement add(ECFieldElement b) {
        long[] z = Nat320.create64();
        SecT283Field.add(this.x, ((SecT283FieldElement) b).x, z);
        return new SecT283FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement addOne() {
        long[] z = Nat320.create64();
        SecT283Field.addOne(this.x, z);
        return new SecT283FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement b) {
        return add(b);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement b) {
        long[] z = Nat320.create64();
        SecT283Field.multiply(this.x, ((SecT283FieldElement) b).x, z);
        return new SecT283FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        return multiplyPlusProduct(b, x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] bx = ((SecT283FieldElement) b).x;
        long[] xx = ((SecT283FieldElement) x2).x;
        long[] yx = ((SecT283FieldElement) y).x;
        long[] tt = Nat.create64(9);
        SecT283Field.multiplyAddToExt(ax, bx, tt);
        SecT283Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat320.create64();
        SecT283Field.reduce(tt, z);
        return new SecT283FieldElement(z);
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
        long[] z = Nat320.create64();
        SecT283Field.square(this.x, z);
        return new SecT283FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squareMinusProduct(ECFieldElement x2, ECFieldElement y) {
        return squarePlusProduct(x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePlusProduct(ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] xx = ((SecT283FieldElement) x2).x;
        long[] yx = ((SecT283FieldElement) y).x;
        long[] tt = Nat.create64(9);
        SecT283Field.squareAddToExt(ax, tt);
        SecT283Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat320.create64();
        SecT283Field.reduce(tt, z);
        return new SecT283FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePow(int pow) {
        if (pow < 1) {
            return this;
        }
        long[] z = Nat320.create64();
        SecT283Field.squareN(this.x, pow, z);
        return new SecT283FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public ECFieldElement halfTrace() {
        long[] z = Nat320.create64();
        SecT283Field.halfTrace(this.x, z);
        return new SecT283FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public boolean hasFastTrace() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public int trace() {
        return SecT283Field.trace(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement invert() {
        long[] z = Nat320.create64();
        SecT283Field.invert(this.x, z);
        return new SecT283FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement sqrt() {
        long[] z = Nat320.create64();
        SecT283Field.sqrt(this.x, z);
        return new SecT283FieldElement(z);
    }

    public int getRepresentation() {
        return 3;
    }

    public int getM() {
        return 283;
    }

    public int getK1() {
        return 5;
    }

    public int getK2() {
        return 7;
    }

    public int getK3() {
        return 12;
    }

    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof SecT283FieldElement)) {
            return false;
        }
        return Nat320.eq64(this.x, ((SecT283FieldElement) other).x);
    }

    public int hashCode() {
        return 2831275 ^ Arrays.hashCode(this.x, 0, 5);
    }
}
