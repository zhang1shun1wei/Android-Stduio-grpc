package com.mi.car.jsse.easysec.pqc.math.ntru.polynomial;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

public class ProductFormPolynomial implements Polynomial {
    private SparseTernaryPolynomial f1;
    private SparseTernaryPolynomial f2;
    private SparseTernaryPolynomial f3;

    public ProductFormPolynomial(SparseTernaryPolynomial f12, SparseTernaryPolynomial f22, SparseTernaryPolynomial f32) {
        this.f1 = f12;
        this.f2 = f22;
        this.f3 = f32;
    }

    public static ProductFormPolynomial generateRandom(int N, int df1, int df2, int df3Ones, int df3NegOnes, SecureRandom random) {
        return new ProductFormPolynomial(SparseTernaryPolynomial.generateRandom(N, df1, df1, random), SparseTernaryPolynomial.generateRandom(N, df2, df2, random), SparseTernaryPolynomial.generateRandom(N, df3Ones, df3NegOnes, random));
    }

    public static ProductFormPolynomial fromBinary(byte[] data, int N, int df1, int df2, int df3Ones, int df3NegOnes) throws IOException {
        return fromBinary(new ByteArrayInputStream(data), N, df1, df2, df3Ones, df3NegOnes);
    }

    public static ProductFormPolynomial fromBinary(InputStream is, int N, int df1, int df2, int df3Ones, int df3NegOnes) throws IOException {
        return new ProductFormPolynomial(SparseTernaryPolynomial.fromBinary(is, N, df1, df1), SparseTernaryPolynomial.fromBinary(is, N, df2, df2), SparseTernaryPolynomial.fromBinary(is, N, df3Ones, df3NegOnes));
    }

    public byte[] toBinary() {
        byte[] f1Bin = this.f1.toBinary();
        byte[] f2Bin = this.f2.toBinary();
        byte[] f3Bin = this.f3.toBinary();
        byte[] all = Arrays.copyOf(f1Bin, f1Bin.length + f2Bin.length + f3Bin.length);
        System.arraycopy(f2Bin, 0, all, f1Bin.length, f2Bin.length);
        System.arraycopy(f3Bin, 0, all, f1Bin.length + f2Bin.length, f3Bin.length);
        return all;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.Polynomial
    public IntegerPolynomial mult(IntegerPolynomial b) {
        IntegerPolynomial c = this.f2.mult(this.f1.mult(b));
        c.add(this.f3.mult(b));
        return c;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.Polynomial
    public BigIntPolynomial mult(BigIntPolynomial b) {
        BigIntPolynomial c = this.f2.mult(this.f1.mult(b));
        c.add(this.f3.mult(b));
        return c;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.Polynomial
    public IntegerPolynomial toIntegerPolynomial() {
        IntegerPolynomial i = this.f1.mult(this.f2.toIntegerPolynomial());
        i.add(this.f3.toIntegerPolynomial());
        return i;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.Polynomial
    public IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
        IntegerPolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }

    public int hashCode() {
        int i = 0;
        int hashCode = ((((this.f1 == null ? 0 : this.f1.hashCode()) + 31) * 31) + (this.f2 == null ? 0 : this.f2.hashCode())) * 31;
        if (this.f3 != null) {
            i = this.f3.hashCode();
        }
        return hashCode + i;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        ProductFormPolynomial other = (ProductFormPolynomial) obj;
        if (this.f1 == null) {
            if (other.f1 != null) {
                return false;
            }
        } else if (!this.f1.equals(other.f1)) {
            return false;
        }
        if (this.f2 == null) {
            if (other.f2 != null) {
                return false;
            }
        } else if (!this.f2.equals(other.f2)) {
            return false;
        }
        return this.f3 == null ? other.f3 == null : this.f3.equals(other.f3);
    }
}
