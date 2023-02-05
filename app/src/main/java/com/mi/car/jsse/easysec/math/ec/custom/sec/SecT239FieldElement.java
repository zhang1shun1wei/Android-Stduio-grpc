package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.raw.Nat256;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class SecT239FieldElement extends ECFieldElement.AbstractF2m {
    protected long[] x;

    public SecT239FieldElement(BigInteger x2) {
        if (x2 == null || x2.signum() < 0 || x2.bitLength() > 239) {
            throw new IllegalArgumentException("x value invalid for SecT239FieldElement");
        }
        this.x = SecT239Field.fromBigInteger(x2);
    }

    public SecT239FieldElement() {
        this.x = Nat256.create64();
    }

    protected SecT239FieldElement(long[] x2) {
        this.x = x2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isOne() {
        return Nat256.isOne64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isZero() {
        return Nat256.isZero64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean testBitZero() {
        return (this.x[0] & 1) != 0;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat256.toBigInteger64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public String getFieldName() {
        return "SecT239Field";
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public int getFieldSize() {
        return 239;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement add(ECFieldElement b) {
        long[] z = Nat256.create64();
        SecT239Field.add(this.x, ((SecT239FieldElement) b).x, z);
        return new SecT239FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement addOne() {
        long[] z = Nat256.create64();
        SecT239Field.addOne(this.x, z);
        return new SecT239FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement b) {
        return add(b);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement b) {
        long[] z = Nat256.create64();
        SecT239Field.multiply(this.x, ((SecT239FieldElement) b).x, z);
        return new SecT239FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        return multiplyPlusProduct(b, x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] bx = ((SecT239FieldElement) b).x;
        long[] xx = ((SecT239FieldElement) x2).x;
        long[] yx = ((SecT239FieldElement) y).x;
        long[] tt = Nat256.createExt64();
        SecT239Field.multiplyAddToExt(ax, bx, tt);
        SecT239Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat256.create64();
        SecT239Field.reduce(tt, z);
        return new SecT239FieldElement(z);
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
        long[] z = Nat256.create64();
        SecT239Field.square(this.x, z);
        return new SecT239FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squareMinusProduct(ECFieldElement x2, ECFieldElement y) {
        return squarePlusProduct(x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePlusProduct(ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] xx = ((SecT239FieldElement) x2).x;
        long[] yx = ((SecT239FieldElement) y).x;
        long[] tt = Nat256.createExt64();
        SecT239Field.squareAddToExt(ax, tt);
        SecT239Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat256.create64();
        SecT239Field.reduce(tt, z);
        return new SecT239FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePow(int pow) {
        if (pow < 1) {
            return this;
        }
        long[] z = Nat256.create64();
        SecT239Field.squareN(this.x, pow, z);
        return new SecT239FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public ECFieldElement halfTrace() {
        long[] z = Nat256.create64();
        SecT239Field.halfTrace(this.x, z);
        return new SecT239FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public boolean hasFastTrace() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public int trace() {
        return SecT239Field.trace(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement invert() {
        long[] z = Nat256.create64();
        SecT239Field.invert(this.x, z);
        return new SecT239FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement sqrt() {
        long[] z = Nat256.create64();
        SecT239Field.sqrt(this.x, z);
        return new SecT239FieldElement(z);
    }

    public int getRepresentation() {
        return 2;
    }

    public int getM() {
        return 239;
    }

    public int getK1() {
        return 158;
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
        if (!(other instanceof SecT239FieldElement)) {
            return false;
        }
        return Nat256.eq64(this.x, ((SecT239FieldElement) other).x);
    }

    public int hashCode() {
        return 23900158 ^ Arrays.hashCode(this.x, 0, 4);
    }
}
