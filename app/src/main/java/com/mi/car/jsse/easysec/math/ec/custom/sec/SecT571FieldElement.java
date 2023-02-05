package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.raw.Nat576;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class SecT571FieldElement extends ECFieldElement.AbstractF2m {
    protected long[] x;

    public SecT571FieldElement(BigInteger x2) {
        if (x2 == null || x2.signum() < 0 || x2.bitLength() > 571) {
            throw new IllegalArgumentException("x value invalid for SecT571FieldElement");
        }
        this.x = SecT571Field.fromBigInteger(x2);
    }

    public SecT571FieldElement() {
        this.x = Nat576.create64();
    }

    protected SecT571FieldElement(long[] x2) {
        this.x = x2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isOne() {
        return Nat576.isOne64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isZero() {
        return Nat576.isZero64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean testBitZero() {
        return (this.x[0] & 1) != 0;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat576.toBigInteger64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public String getFieldName() {
        return "SecT571Field";
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public int getFieldSize() {
        return 571;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement add(ECFieldElement b) {
        long[] z = Nat576.create64();
        SecT571Field.add(this.x, ((SecT571FieldElement) b).x, z);
        return new SecT571FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement addOne() {
        long[] z = Nat576.create64();
        SecT571Field.addOne(this.x, z);
        return new SecT571FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement b) {
        return add(b);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement b) {
        long[] z = Nat576.create64();
        SecT571Field.multiply(this.x, ((SecT571FieldElement) b).x, z);
        return new SecT571FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        return multiplyPlusProduct(b, x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] bx = ((SecT571FieldElement) b).x;
        long[] xx = ((SecT571FieldElement) x2).x;
        long[] yx = ((SecT571FieldElement) y).x;
        long[] tt = Nat576.createExt64();
        SecT571Field.multiplyAddToExt(ax, bx, tt);
        SecT571Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat576.create64();
        SecT571Field.reduce(tt, z);
        return new SecT571FieldElement(z);
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
        long[] z = Nat576.create64();
        SecT571Field.square(this.x, z);
        return new SecT571FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squareMinusProduct(ECFieldElement x2, ECFieldElement y) {
        return squarePlusProduct(x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePlusProduct(ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] xx = ((SecT571FieldElement) x2).x;
        long[] yx = ((SecT571FieldElement) y).x;
        long[] tt = Nat576.createExt64();
        SecT571Field.squareAddToExt(ax, tt);
        SecT571Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat576.create64();
        SecT571Field.reduce(tt, z);
        return new SecT571FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePow(int pow) {
        if (pow < 1) {
            return this;
        }
        long[] z = Nat576.create64();
        SecT571Field.squareN(this.x, pow, z);
        return new SecT571FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public ECFieldElement halfTrace() {
        long[] z = Nat576.create64();
        SecT571Field.halfTrace(this.x, z);
        return new SecT571FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public boolean hasFastTrace() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public int trace() {
        return SecT571Field.trace(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement invert() {
        long[] z = Nat576.create64();
        SecT571Field.invert(this.x, z);
        return new SecT571FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement sqrt() {
        long[] z = Nat576.create64();
        SecT571Field.sqrt(this.x, z);
        return new SecT571FieldElement(z);
    }

    public int getRepresentation() {
        return 3;
    }

    public int getM() {
        return 571;
    }

    public int getK1() {
        return 2;
    }

    public int getK2() {
        return 5;
    }

    public int getK3() {
        return 10;
    }

    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof SecT571FieldElement)) {
            return false;
        }
        return Nat576.eq64(this.x, ((SecT571FieldElement) other).x);
    }

    public int hashCode() {
        return 5711052 ^ Arrays.hashCode(this.x, 0, 9);
    }
}
