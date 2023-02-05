package com.mi.car.jsse.easysec.pqc.math.ntru.polynomial;

public interface TernaryPolynomial extends Polynomial {
    void clear();

    int[] getNegOnes();

    int[] getOnes();

    @Override // com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.Polynomial
    IntegerPolynomial mult(IntegerPolynomial integerPolynomial);

    int size();
}
