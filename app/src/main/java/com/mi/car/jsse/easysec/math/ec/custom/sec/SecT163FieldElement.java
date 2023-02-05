package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.raw.Nat192;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class SecT163FieldElement extends ECFieldElement.AbstractF2m {
    protected long[] x;

    public SecT163FieldElement(BigInteger x2) {
        if (x2 == null || x2.signum() < 0 || x2.bitLength() > 163) {
            throw new IllegalArgumentException("x value invalid for SecT163FieldElement");
        }
        this.x = SecT163Field.fromBigInteger(x2);
    }

    public SecT163FieldElement() {
        this.x = Nat192.create64();
    }

    protected SecT163FieldElement(long[] x2) {
        this.x = x2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isOne() {
        return Nat192.isOne64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isZero() {
        return Nat192.isZero64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean testBitZero() {
        return (this.x[0] & 1) != 0;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat192.toBigInteger64(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public String getFieldName() {
        return "SecT163Field";
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public int getFieldSize() {
        return 163;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement add(ECFieldElement b) {
        long[] z = Nat192.create64();
        SecT163Field.add(this.x, ((SecT163FieldElement) b).x, z);
        return new SecT163FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement addOne() {
        long[] z = Nat192.create64();
        SecT163Field.addOne(this.x, z);
        return new SecT163FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement b) {
        return add(b);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement b) {
        long[] z = Nat192.create64();
        SecT163Field.multiply(this.x, ((SecT163FieldElement) b).x, z);
        return new SecT163FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        return multiplyPlusProduct(b, x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] bx = ((SecT163FieldElement) b).x;
        long[] xx = ((SecT163FieldElement) x2).x;
        long[] yx = ((SecT163FieldElement) y).x;
        long[] tt = Nat192.createExt64();
        SecT163Field.multiplyAddToExt(ax, bx, tt);
        SecT163Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat192.create64();
        SecT163Field.reduce(tt, z);
        return new SecT163FieldElement(z);
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
        long[] z = Nat192.create64();
        SecT163Field.square(this.x, z);
        return new SecT163FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squareMinusProduct(ECFieldElement x2, ECFieldElement y) {
        return squarePlusProduct(x2, y);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePlusProduct(ECFieldElement x2, ECFieldElement y) {
        long[] ax = this.x;
        long[] xx = ((SecT163FieldElement) x2).x;
        long[] yx = ((SecT163FieldElement) y).x;
        long[] tt = Nat192.createExt64();
        SecT163Field.squareAddToExt(ax, tt);
        SecT163Field.multiplyAddToExt(xx, yx, tt);
        long[] z = Nat192.create64();
        SecT163Field.reduce(tt, z);
        return new SecT163FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement squarePow(int pow) {
        if (pow < 1) {
            return this;
        }
        long[] z = Nat192.create64();
        SecT163Field.squareN(this.x, pow, z);
        return new SecT163FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public ECFieldElement halfTrace() {
        long[] z = Nat192.create64();
        SecT163Field.halfTrace(this.x, z);
        return new SecT163FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public boolean hasFastTrace() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement.AbstractF2m
    public int trace() {
        return SecT163Field.trace(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement invert() {
        long[] z = Nat192.create64();
        SecT163Field.invert(this.x, z);
        return new SecT163FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement sqrt() {
        long[] z = Nat192.create64();
        SecT163Field.sqrt(this.x, z);
        return new SecT163FieldElement(z);
    }

    public int getRepresentation() {
        return 3;
    }

    public int getM() {
        return 163;
    }

    public int getK1() {
        return 3;
    }

    public int getK2() {
        return 6;
    }

    public int getK3() {
        return 7;
    }

    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof SecT163FieldElement)) {
            return false;
        }
        return Nat192.eq64(this.x, ((SecT163FieldElement) other).x);
    }

    public int hashCode() {
        return 163763 ^ Arrays.hashCode(this.x, 0, 3);
    }
}
