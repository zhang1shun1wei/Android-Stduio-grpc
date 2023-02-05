package com.mi.car.jsse.easysec.math.ec.custom.sec;

import com.mi.car.jsse.easysec.math.ec.ECFieldElement;
import com.mi.car.jsse.easysec.math.raw.Nat256;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.math.BigInteger;

public class SecP256K1FieldElement extends ECFieldElement.AbstractFp {
    public static final BigInteger Q = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"));
    protected int[] x;

    public SecP256K1FieldElement(BigInteger x2) {
        if (x2 == null || x2.signum() < 0 || x2.compareTo(Q) >= 0) {
            throw new IllegalArgumentException("x value invalid for SecP256K1FieldElement");
        }
        this.x = SecP256K1Field.fromBigInteger(x2);
    }

    public SecP256K1FieldElement() {
        this.x = Nat256.create();
    }

    protected SecP256K1FieldElement(int[] x2) {
        this.x = x2;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isZero() {
        return Nat256.isZero(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean isOne() {
        return Nat256.isOne(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public boolean testBitZero() {
        return Nat256.getBit(this.x, 0) == 1;
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public BigInteger toBigInteger() {
        return Nat256.toBigInteger(this.x);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public String getFieldName() {
        return "SecP256K1Field";
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public int getFieldSize() {
        return Q.bitLength();
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement add(ECFieldElement b) {
        int[] z = Nat256.create();
        SecP256K1Field.add(this.x, ((SecP256K1FieldElement) b).x, z);
        return new SecP256K1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement addOne() {
        int[] z = Nat256.create();
        SecP256K1Field.addOne(this.x, z);
        return new SecP256K1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement subtract(ECFieldElement b) {
        int[] z = Nat256.create();
        SecP256K1Field.subtract(this.x, ((SecP256K1FieldElement) b).x, z);
        return new SecP256K1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement multiply(ECFieldElement b) {
        int[] z = Nat256.create();
        SecP256K1Field.multiply(this.x, ((SecP256K1FieldElement) b).x, z);
        return new SecP256K1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement divide(ECFieldElement b) {
        int[] z = Nat256.create();
        SecP256K1Field.inv(((SecP256K1FieldElement) b).x, z);
        SecP256K1Field.multiply(z, this.x, z);
        return new SecP256K1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement negate() {
        int[] z = Nat256.create();
        SecP256K1Field.negate(this.x, z);
        return new SecP256K1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement square() {
        int[] z = Nat256.create();
        SecP256K1Field.square(this.x, z);
        return new SecP256K1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement invert() {
        int[] z = Nat256.create();
        SecP256K1Field.inv(this.x, z);
        return new SecP256K1FieldElement(z);
    }

    @Override // com.mi.car.jsse.easysec.math.ec.ECFieldElement
    public ECFieldElement sqrt() {
        int[] x1 = this.x;
        if (Nat256.isZero(x1) || Nat256.isOne(x1)) {
            return this;
        }
        int[] tt0 = Nat256.createExt();
        int[] x2 = Nat256.create();
        SecP256K1Field.square(x1, x2, tt0);
        SecP256K1Field.multiply(x2, x1, x2, tt0);
        int[] x3 = Nat256.create();
        SecP256K1Field.square(x2, x3, tt0);
        SecP256K1Field.multiply(x3, x1, x3, tt0);
        int[] x6 = Nat256.create();
        SecP256K1Field.squareN(x3, 3, x6, tt0);
        SecP256K1Field.multiply(x6, x3, x6, tt0);
        SecP256K1Field.squareN(x6, 3, x6, tt0);
        SecP256K1Field.multiply(x6, x3, x6, tt0);
        SecP256K1Field.squareN(x6, 2, x6, tt0);
        SecP256K1Field.multiply(x6, x2, x6, tt0);
        int[] x22 = Nat256.create();
        SecP256K1Field.squareN(x6, 11, x22, tt0);
        SecP256K1Field.multiply(x22, x6, x22, tt0);
        SecP256K1Field.squareN(x22, 22, x6, tt0);
        SecP256K1Field.multiply(x6, x22, x6, tt0);
        int[] x88 = Nat256.create();
        SecP256K1Field.squareN(x6, 44, x88, tt0);
        SecP256K1Field.multiply(x88, x6, x88, tt0);
        int[] x176 = Nat256.create();
        SecP256K1Field.squareN(x88, 88, x176, tt0);
        SecP256K1Field.multiply(x176, x88, x176, tt0);
        SecP256K1Field.squareN(x176, 44, x88, tt0);
        SecP256K1Field.multiply(x88, x6, x88, tt0);
        SecP256K1Field.squareN(x88, 3, x6, tt0);
        SecP256K1Field.multiply(x6, x3, x6, tt0);
        SecP256K1Field.squareN(x6, 23, x6, tt0);
        SecP256K1Field.multiply(x6, x22, x6, tt0);
        SecP256K1Field.squareN(x6, 6, x6, tt0);
        SecP256K1Field.multiply(x6, x2, x6, tt0);
        SecP256K1Field.squareN(x6, 2, x6, tt0);
        SecP256K1Field.square(x6, x2, tt0);
        if (Nat256.eq(x1, x2)) {
            return new SecP256K1FieldElement(x6);
        }
        return null;
    }

    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof SecP256K1FieldElement)) {
            return false;
        }
        return Nat256.eq(this.x, ((SecP256K1FieldElement) other).x);
    }

    public int hashCode() {
        return Q.hashCode() ^ Arrays.hashCode(this.x, 0, 8);
    }
}
