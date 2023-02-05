package com.mi.car.jsse.easysec.pqc.math.ntru.polynomial;

import com.mi.car.jsse.easysec.util.Arrays;

public class LongPolynomial2 {
    private long[] coeffs;
    private int numCoeffs;

    public LongPolynomial2(IntegerPolynomial p) {
        long c1;
        this.numCoeffs = p.coeffs.length;
        this.coeffs = new long[((this.numCoeffs + 1) / 2)];
        int idx = 0;
        int pIdx = 0;
        while (pIdx < this.numCoeffs) {
            int pIdx2 = pIdx + 1;
            int c0 = p.coeffs[pIdx];
            while (c0 < 0) {
                c0 += 2048;
            }
            if (pIdx2 < this.numCoeffs) {
                pIdx = pIdx2 + 1;
                c1 = (long) p.coeffs[pIdx2];
            } else {
                c1 = 0;
                pIdx = pIdx2;
            }
            while (c1 < 0) {
                c1 += 2048;
            }
            this.coeffs[idx] = ((long) c0) + (c1 << 24);
            idx++;
        }
    }

    private LongPolynomial2(long[] coeffs2) {
        this.coeffs = coeffs2;
    }

    private LongPolynomial2(int N) {
        this.coeffs = new long[N];
    }

    public LongPolynomial2 mult(LongPolynomial2 poly2) {
        int N = this.coeffs.length;
        if (poly2.coeffs.length == N && this.numCoeffs == poly2.numCoeffs) {
            LongPolynomial2 c = multRecursive(poly2);
            if (c.coeffs.length > N) {
                if (this.numCoeffs % 2 == 0) {
                    for (int k = N; k < c.coeffs.length; k++) {
                        c.coeffs[k - N] = (c.coeffs[k - N] + c.coeffs[k]) & 34342963199L;
                    }
                    c.coeffs = Arrays.copyOf(c.coeffs, N);
                } else {
                    for (int k2 = N; k2 < c.coeffs.length; k2++) {
                        c.coeffs[k2 - N] = c.coeffs[k2 - N] + (c.coeffs[k2 - 1] >> 24);
                        c.coeffs[k2 - N] = c.coeffs[k2 - N] + ((c.coeffs[k2] & 2047) << 24);
                        long[] jArr = c.coeffs;
                        int i = k2 - N;
                        jArr[i] = jArr[i] & 34342963199L;
                    }
                    c.coeffs = Arrays.copyOf(c.coeffs, N);
                    long[] jArr2 = c.coeffs;
                    int length = c.coeffs.length - 1;
                    jArr2[length] = jArr2[length] & 2047;
                }
            }
            LongPolynomial2 c2 = new LongPolynomial2(c.coeffs);
            c2.numCoeffs = this.numCoeffs;
            return c2;
        }
        throw new IllegalArgumentException("Number of coefficients must be the same");
    }

    public IntegerPolynomial toIntegerPolynomial() {
        int[] intCoeffs = new int[this.numCoeffs];
        int uIdx = 0;
        for (int i = 0; i < this.coeffs.length; i++) {
            int uIdx2 = uIdx + 1;
            intCoeffs[uIdx] = (int) (this.coeffs[i] & 2047);
            if (uIdx2 < this.numCoeffs) {
                uIdx = uIdx2 + 1;
                intCoeffs[uIdx2] = (int) ((this.coeffs[i] >> 24) & 2047);
            } else {
                uIdx = uIdx2;
            }
        }
        return new IntegerPolynomial(intCoeffs);
    }

    private LongPolynomial2 multRecursive(LongPolynomial2 poly2) {
        LongPolynomial2 c;
        long[] a = this.coeffs;
        long[] b = poly2.coeffs;
        int n = poly2.coeffs.length;
        if (n <= 32) {
            int cn2 = n * 2;
            c = new LongPolynomial2(new long[cn2]);
            for (int k = 0; k < cn2; k++) {
                for (int i = Math.max(0, (k - n) + 1); i <= Math.min(k, n - 1); i++) {
                    long c0 = a[k - i] * b[i];
                    c.coeffs[k] = (c.coeffs[k] + (c0 & (34342961152L + (2047 & c0)))) & 34342963199L;
                    c.coeffs[k + 1] = (c.coeffs[k + 1] + ((c0 >>> 48) & 2047)) & 34342963199L;
                }
            }
        } else {
            int n1 = n / 2;
            LongPolynomial2 a1 = new LongPolynomial2(Arrays.copyOf(a, n1));
            LongPolynomial2 a2 = new LongPolynomial2(Arrays.copyOfRange(a, n1, n));
            LongPolynomial2 b1 = new LongPolynomial2(Arrays.copyOf(b, n1));
            LongPolynomial2 b2 = new LongPolynomial2(Arrays.copyOfRange(b, n1, n));
            LongPolynomial2 A = (LongPolynomial2) a1.clone();
            A.add(a2);
            LongPolynomial2 B = (LongPolynomial2) b1.clone();
            B.add(b2);
            LongPolynomial2 c1 = a1.multRecursive(b1);
            LongPolynomial2 c2 = a2.multRecursive(b2);
            LongPolynomial2 c3 = A.multRecursive(B);
            c3.sub(c1);
            c3.sub(c2);
            c = new LongPolynomial2(n * 2);
            for (int i2 = 0; i2 < c1.coeffs.length; i2++) {
                c.coeffs[i2] = c1.coeffs[i2] & 34342963199L;
            }
            for (int i3 = 0; i3 < c3.coeffs.length; i3++) {
                c.coeffs[n1 + i3] = (c.coeffs[n1 + i3] + c3.coeffs[i3]) & 34342963199L;
            }
            for (int i4 = 0; i4 < c2.coeffs.length; i4++) {
                c.coeffs[(n1 * 2) + i4] = (c.coeffs[(n1 * 2) + i4] + c2.coeffs[i4]) & 34342963199L;
            }
        }
        return c;
    }

    private void add(LongPolynomial2 b) {
        if (b.coeffs.length > this.coeffs.length) {
            this.coeffs = Arrays.copyOf(this.coeffs, b.coeffs.length);
        }
        for (int i = 0; i < b.coeffs.length; i++) {
            this.coeffs[i] = (this.coeffs[i] + b.coeffs[i]) & 34342963199L;
        }
    }

    private void sub(LongPolynomial2 b) {
        if (b.coeffs.length > this.coeffs.length) {
            this.coeffs = Arrays.copyOf(this.coeffs, b.coeffs.length);
        }
        for (int i = 0; i < b.coeffs.length; i++) {
            this.coeffs[i] = ((140737496743936L + this.coeffs[i]) - b.coeffs[i]) & 34342963199L;
        }
    }

    public void subAnd(LongPolynomial2 b, int mask) {
        long longMask = (((long) mask) << 24) + ((long) mask);
        for (int i = 0; i < b.coeffs.length; i++) {
            this.coeffs[i] = ((140737496743936L + this.coeffs[i]) - b.coeffs[i]) & longMask;
        }
    }

    public void mult2And(int mask) {
        long longMask = (((long) mask) << 24) + ((long) mask);
        for (int i = 0; i < this.coeffs.length; i++) {
            this.coeffs[i] = (this.coeffs[i] << 1) & longMask;
        }
    }

    public Object clone() {
        LongPolynomial2 p = new LongPolynomial2((long[]) this.coeffs.clone());
        p.numCoeffs = this.numCoeffs;
        return p;
    }

    public boolean equals(Object obj) {
        if (obj instanceof LongPolynomial2) {
            return Arrays.areEqual(this.coeffs, ((LongPolynomial2) obj).coeffs);
        }
        return false;
    }
}
