package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.raw.Nat128;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class SecT113FieldElement extends ECFieldElement.AbstractF2m {
    protected long[] x;

    public SecT113FieldElement(BigInteger x2) {
        if (x2 == null || x2.signum() < 0 || x2.bitLength() > 113) {
            throw new IllegalArgumentException("x value invalid for SecT113FieldElement");
        }
        this.x = SecT113Field.fromBigInteger(x2);
    }

    public SecT113FieldElement() {
        this.x = Nat128.create64();
    }

    protected SecT113FieldElement(long[] x2) {
        this.x = x2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isOne() {
        return Nat128.isOne64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isZero() {
        return Nat128.isZero64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean testBitZero() {
        return (this.x[0] & 1) != 0;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat128.toBigInteger64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public String getFieldName() {
        return "SecT113Field";
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public int getFieldSize() {
        return 113;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement add(ECFieldElement b) {
        long[] z = Nat128.create64();
        SecT113Field.add(this.x, ((SecT113FieldElement) b).x, z);
        return new SecT113FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement addOne() {
        long[] z = Nat128.create64();
        SecT113Field.addOne(this.x, z);
        return new SecT113FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement b) {
        return add(b);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement b) {
        long[] z = Nat128.create64();
        SecT113Field.multiply(this.x, ((SecT113FieldElement) b).x, z);
        return new SecT113FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        return multiplyPlusProduct(b, x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] bx = ((SecT113FieldElement) b).x;
        long[] xx = ((SecT113FieldElement) x2).x;
        long[] yx = ((SecT113FieldElement) y).x;
        long[] tt = Nat128.createExt64();
        SecT113Field.multiplyAddToExt(ax, bx, tt);
        SecT113Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat128.create64();
        SecT113Field.reduce(tt, z);
        return new SecT113FieldElement(z);
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
        long[] z = Nat128.create64();
        SecT113Field.square(this.x, z);
        return new SecT113FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squareMinusProduct(ECFieldElement x2, ECFieldElement y) {
        return squarePlusProduct(x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePlusProduct(ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] xx = ((SecT113FieldElement) x2).x;
        long[] yx = ((SecT113FieldElement) y).x;
        long[] tt = Nat128.createExt64();
        SecT113Field.squareAddToExt(ax, tt);
        SecT113Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat128.create64();
        SecT113Field.reduce(tt, z);
        return new SecT113FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePow(int pow) {
        if (pow < 1) {
            return this;
        }
        long[] z = Nat128.create64();
        SecT113Field.squareN(this.x, pow, z);
        return new SecT113FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public ECFieldElement halfTrace() {
        long[] z = Nat128.create64();
        SecT113Field.halfTrace(this.x, z);
        return new SecT113FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public boolean hasFastTrace() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public int trace() {
        return SecT113Field.trace(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement invert() {
        long[] z = Nat128.create64();
        SecT113Field.invert(this.x, z);
        return new SecT113FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement sqrt() {
        long[] z = Nat128.create64();
        SecT113Field.sqrt(this.x, z);
        return new SecT113FieldElement(z);
    }

    public int getRepresentation() {
        return 2;
    }

    public int getM() {
        return 113;
    }

    public int getK1() {
        return 9;
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
        if (!(other instanceof SecT113FieldElement)) {
            return false;
        }
        return Nat128.eq64(this.x, ((SecT113FieldElement) other).x);
    }

    public int hashCode() {
        return 113009 ^ Arrays.hashCode(this.x, 0, 2);
    }
}
