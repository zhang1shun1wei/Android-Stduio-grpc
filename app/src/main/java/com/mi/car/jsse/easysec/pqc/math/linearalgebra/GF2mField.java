package com.mi.car.jsse.easysec.pqc.math.linearalgebra;

import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import java.security.SecureRandom;

public class GF2mField {
    private int degree = 0;
    private int polynomial;

    public GF2mField(int degree2) {
        if (degree2 >= 32) {
            throw new IllegalArgumentException(" Error: the degree of field is too large ");
        } else if (degree2 < 1) {
            throw new IllegalArgumentException(" Error: the degree of field is non-positive ");
        } else {
            this.degree = degree2;
            this.polynomial = PolynomialRingGF2.getIrreduciblePolynomial(degree2);
        }
    }

    public GF2mField(int degree2, int poly) {
        if (degree2 != PolynomialRingGF2.degree(poly)) {
            throw new IllegalArgumentException(" Error: the degree is not correct");
        } else if (!PolynomialRingGF2.isIrreducible(poly)) {
            throw new IllegalArgumentException(" Error: given polynomial is reducible");
        } else {
            this.degree = degree2;
            this.polynomial = poly;
        }
    }

    public GF2mField(byte[] enc) {
        if (enc.length != 4) {
            throw new IllegalArgumentException("byte array is not an encoded finite field");
        }
        this.polynomial = LittleEndianConversions.OS2IP(enc);
        if (!PolynomialRingGF2.isIrreducible(this.polynomial)) {
            throw new IllegalArgumentException("byte array is not an encoded finite field");
        }
        this.degree = PolynomialRingGF2.degree(this.polynomial);
    }

    public GF2mField(GF2mField field) {
        this.degree = field.degree;
        this.polynomial = field.polynomial;
    }

    public int getDegree() {
        return this.degree;
    }

    public int getPolynomial() {
        return this.polynomial;
    }

    public byte[] getEncoded() {
        return LittleEndianConversions.I2OSP(this.polynomial);
    }

    public int add(int a, int b) {
        return a ^ b;
    }

    public int mult(int a, int b) {
        return PolynomialRingGF2.modMultiply(a, b, this.polynomial);
    }

    public int exp(int a, int k) {
        if (k == 0) {
            return 1;
        }
        if (a == 0) {
            return 0;
        }
        if (a == 1) {
            return 1;
        }
        int result = 1;
        if (k < 0) {
            a = inverse(a);
            k = -k;
        }
        while (k != 0) {
            if ((k & 1) == 1) {
                result = mult(result, a);
            }
            a = mult(a, a);
            k >>>= 1;
        }
        return result;
    }

    public int inverse(int a) {
        return exp(a, (1 << this.degree) - 2);
    }

    public int sqRoot(int a) {
        for (int i = 1; i < this.degree; i++) {
            a = mult(a, a);
        }
        return a;
    }

    public int getRandomElement(SecureRandom sr) {
        return RandUtils.nextInt(sr, 1 << this.degree);
    }

    public int getRandomNonZeroElement() {
        return getRandomNonZeroElement(CryptoServicesRegistrar.getSecureRandom());
    }

    public int getRandomNonZeroElement(SecureRandom sr) {
        int count = 0;
        int result = RandUtils.nextInt(sr, 1 << this.degree);
        while (result == 0 && count < 1048576) {
            result = RandUtils.nextInt(sr, 1 << this.degree);
            count++;
        }
        if (count == 1048576) {
            return 1;
        }
        return result;
    }

    public boolean isElementOfThisField(int e) {
        return this.degree == 31 ? e >= 0 : e >= 0 && e < (1 << this.degree);
    }

    public String elementToStr(int a) {
        String s = "";
        for (int i = 0; i < this.degree; i++) {
            s = (((byte) a) & 1) == 0 ? "0" + s : "1" + s;
            a >>>= 1;
        }
        return s;
    }

    public boolean equals(Object other) {
        if (other == null || !(other instanceof GF2mField)) {
            return false;
        }
        GF2mField otherField = (GF2mField) other;
        if (this.degree == otherField.degree && this.polynomial == otherField.polynomial) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return this.polynomial;
    }

    public String toString() {
        return "Finite Field GF(2^" + this.degree + ") = GF(2)[X]/<" + polyToString(this.polynomial) + "> ";
    }

    private static String polyToString(int p) {
        String str = "";
        if (p == 0) {
            return "0";
        }
        if (((byte) (p & 1)) == 1) {
            str = "1";
        }
        int p2 = p >>> 1;
        int i = 1;
        while (p2 != 0) {
            if (((byte) (p2 & 1)) == 1) {
                str = str + "+x^" + i;
            }
            p2 >>>= 1;
            i++;
        }
        return str;
    }
}
