package com.mi.car.jsse.easysec.pqc.math.ntru.polynomial;

import com.mi.car.jsse.easysec.pqc.math.ntru.util.Util;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;

public class DenseTernaryPolynomial extends IntegerPolynomial implements TernaryPolynomial {
    DenseTernaryPolynomial(int N) {
        super(N);
        checkTernarity();
    }

    public DenseTernaryPolynomial(IntegerPolynomial intPoly) {
        this(intPoly.coeffs);
    }

    public DenseTernaryPolynomial(int[] coeffs) {
        super(coeffs);
        checkTernarity();
    }

    private void checkTernarity() {
        for (int i = 0; i != this.coeffs.length; i++) {
            int c = this.coeffs[i];
            if (c < -1 || c > 1) {
                throw new IllegalStateException("Illegal value: " + c + ", must be one of {-1, 0, 1}");
            }
        }
    }

    public static DenseTernaryPolynomial generateRandom(int N, int numOnes, int numNegOnes, SecureRandom random) {
        return new DenseTernaryPolynomial(Util.generateRandomTernary(N, numOnes, numNegOnes, random));
    }

    public static DenseTernaryPolynomial generateRandom(int N, SecureRandom random) {
        DenseTernaryPolynomial poly = new DenseTernaryPolynomial(N);
        for (int i = 0; i < N; i++) {
            poly.coeffs[i] = random.nextInt(3) - 1;
        }
        return poly;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.Polynomial, com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.IntegerPolynomial
    public IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
        if (modulus != 2048) {
            return super.mult(poly2, modulus);
        }
        IntegerPolynomial poly2Pos = (IntegerPolynomial) poly2.clone();
        poly2Pos.modPositive(2048);
        return new LongPolynomial5(poly2Pos).mult(this).toIntegerPolynomial();
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.TernaryPolynomial
    public int[] getOnes() {
        int onesIdx;
        int N = this.coeffs.length;
        int[] ones = new int[N];
        int i = 0;
        int onesIdx2 = 0;
        while (i < N) {
            if (this.coeffs[i] == 1) {
                onesIdx = onesIdx2 + 1;
                ones[onesIdx2] = i;
            } else {
                onesIdx = onesIdx2;
            }
            i++;
            onesIdx2 = onesIdx;
        }
        return Arrays.copyOf(ones, onesIdx2);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.TernaryPolynomial
    public int[] getNegOnes() {
        int negOnesIdx;
        int N = this.coeffs.length;
        int[] negOnes = new int[N];
        int i = 0;
        int negOnesIdx2 = 0;
        while (i < N) {
            if (this.coeffs[i] == -1) {
                negOnesIdx = negOnesIdx2 + 1;
                negOnes[negOnesIdx2] = i;
            } else {
                negOnesIdx = negOnesIdx2;
            }
            i++;
            negOnesIdx2 = negOnesIdx;
        }
        return Arrays.copyOf(negOnes, negOnesIdx2);
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.ntru.polynomial.TernaryPolynomial
    public int size() {
        return this.coeffs.length;
    }
}
