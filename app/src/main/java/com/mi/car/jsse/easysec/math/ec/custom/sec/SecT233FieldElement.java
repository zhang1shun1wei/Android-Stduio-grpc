package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.raw.Nat256;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class SecT233FieldElement extends ECFieldElement.AbstractF2m {
    protected long[] x;

    public SecT233FieldElement(BigInteger x2) {
        if (x2 == null || x2.signum() < 0 || x2.bitLength() > 233) {
            throw new IllegalArgumentException("x value invalid for SecT233FieldElement");
        }
        this.x = SecT233Field.fromBigInteger(x2);
    }

    public SecT233FieldElement() {
        this.x = Nat256.create64();
    }

    protected SecT233FieldElement(long[] x2) {
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
        return "SecT233Field";
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public int getFieldSize() {
        return 233;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement add(ECFieldElement b) {
        long[] z = Nat256.create64();
        SecT233Field.add(this.x, ((SecT233FieldElement) b).x, z);
        return new SecT233FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement addOne() {
        long[] z = Nat256.create64();
        SecT233Field.addOne(this.x, z);
        return new SecT233FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement b) {
        return add(b);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement b) {
        long[] z = Nat256.create64();
        SecT233Field.multiply(this.x, ((SecT233FieldElement) b).x, z);
        return new SecT233FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        return multiplyPlusProduct(b, x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] bx = ((SecT233FieldElement) b).x;
        long[] xx = ((SecT233FieldElement) x2).x;
        long[] yx = ((SecT233FieldElement) y).x;
        long[] tt = Nat256.createExt64();
        SecT233Field.multiplyAddToExt(ax, bx, tt);
        SecT233Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat256.create64();
        SecT233Field.reduce(tt, z);
        return new SecT233FieldElement(z);
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
        SecT233Field.square(this.x, z);
        return new SecT233FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squareMinusProduct(ECFieldElement x2, ECFieldElement y) {
        return squarePlusProduct(x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePlusProduct(ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] xx = ((SecT233FieldElement) x2).x;
        long[] yx = ((SecT233FieldElement) y).x;
        long[] tt = Nat256.createExt64();
        SecT233Field.squareAddToExt(ax, tt);
        SecT233Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat256.create64();
        SecT233Field.reduce(tt, z);
        return new SecT233FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePow(int pow) {
        if (pow < 1) {
            return this;
        }
        long[] z = Nat256.create64();
        SecT233Field.squareN(this.x, pow, z);
        return new SecT233FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public ECFieldElement halfTrace() {
        long[] z = Nat256.create64();
        SecT233Field.halfTrace(this.x, z);
        return new SecT233FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public boolean hasFastTrace() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public int trace() {
        return SecT233Field.trace(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement invert() {
        long[] z = Nat256.create64();
        SecT233Field.invert(this.x, z);
        return new SecT233FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement sqrt() {
        long[] z = Nat256.create64();
        SecT233Field.sqrt(this.x, z);
        return new SecT233FieldElement(z);
    }

    public int getRepresentation() {
        return 2;
    }

    public int getM() {
        return 233;
    }

    public int getK1() {
        return 74;
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
        if (!(other instanceof SecT233FieldElement)) {
            return false;
        }
        return Nat256.eq64(this.x, ((SecT233FieldElement) other).x);
    }

    public int hashCode() {
        return 2330074 ^ Arrays.hashCode(this.x, 0, 4);
    }
}
