package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.raw.Nat256;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class SecT193FieldElement extends ECFieldElement.AbstractF2m {
    protected long[] x;

    public SecT193FieldElement(BigInteger x2) {
        if (x2 == null || x2.signum() < 0 || x2.bitLength() > 193) {
            throw new IllegalArgumentException("x value invalid for SecT193FieldElement");
        }
        this.x = SecT193Field.fromBigInteger(x2);
    }

    public SecT193FieldElement() {
        this.x = Nat256.create64();
    }

    protected SecT193FieldElement(long[] x2) {
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
        return "SecT193Field";
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public int getFieldSize() {
        return 193;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement add(ECFieldElement b) {
        long[] z = Nat256.create64();
        SecT193Field.add(this.x, ((SecT193FieldElement) b).x, z);
        return new SecT193FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement addOne() {
        long[] z = Nat256.create64();
        SecT193Field.addOne(this.x, z);
        return new SecT193FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement b) {
        return add(b);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement b) {
        long[] z = Nat256.create64();
        SecT193Field.multiply(this.x, ((SecT193FieldElement) b).x, z);
        return new SecT193FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        return multiplyPlusProduct(b, x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] bx = ((SecT193FieldElement) b).x;
        long[] xx = ((SecT193FieldElement) x2).x;
        long[] yx = ((SecT193FieldElement) y).x;
        long[] tt = Nat256.createExt64();
        SecT193Field.multiplyAddToExt(ax, bx, tt);
        SecT193Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat256.create64();
        SecT193Field.reduce(tt, z);
        return new SecT193FieldElement(z);
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
        SecT193Field.square(this.x, z);
        return new SecT193FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squareMinusProduct(ECFieldElement x2, ECFieldElement y) {
        return squarePlusProduct(x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePlusProduct(ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] xx = ((SecT193FieldElement) x2).x;
        long[] yx = ((SecT193FieldElement) y).x;
        long[] tt = Nat256.createExt64();
        SecT193Field.squareAddToExt(ax, tt);
        SecT193Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat256.create64();
        SecT193Field.reduce(tt, z);
        return new SecT193FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePow(int pow) {
        if (pow < 1) {
            return this;
        }
        long[] z = Nat256.create64();
        SecT193Field.squareN(this.x, pow, z);
        return new SecT193FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public ECFieldElement halfTrace() {
        long[] z = Nat256.create64();
        SecT193Field.halfTrace(this.x, z);
        return new SecT193FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public boolean hasFastTrace() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public int trace() {
        return SecT193Field.trace(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement invert() {
        long[] z = Nat256.create64();
        SecT193Field.invert(this.x, z);
        return new SecT193FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement sqrt() {
        long[] z = Nat256.create64();
        SecT193Field.sqrt(this.x, z);
        return new SecT193FieldElement(z);
    }

    public int getRepresentation() {
        return 2;
    }

    public int getM() {
        return 193;
    }

    public int getK1() {
        return 15;
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
        if (!(other instanceof SecT193FieldElement)) {
            return false;
        }
        return Nat256.eq64(this.x, ((SecT193FieldElement) other).x);
    }

    public int hashCode() {
        return 1930015 ^ Arrays.hashCode(this.x, 0, 4);
    }
}
