package com.mi.car.jsse.easysec.pqc.math.linearalgebra;

import java.lang.reflect.Array;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Vector;

public class GF2nONBField extends GF2nField {
    private static final int MAXLONG = 64;
    private int mBit;
    private int mLength;
    int[][] mMult;
    private int mType;

    public GF2nONBField(int deg, SecureRandom random) throws RuntimeException {
        super(random);
        if (deg < 3) {
            throw new IllegalArgumentException("k must be at least 3");
        }
        this.mDegree = deg;
        this.mLength = this.mDegree / 64;
        this.mBit = this.mDegree & 63;
        if (this.mBit == 0) {
            this.mBit = 64;
        } else {
            this.mLength++;
        }
        computeType();
        if (this.mType < 3) {
            this.mMult = (int[][]) Array.newInstance(Integer.TYPE, this.mDegree, 2);
            for (int i = 0; i < this.mDegree; i++) {
                this.mMult[i][0] = -1;
                this.mMult[i][1] = -1;
            }
            computeMultMatrix();
            computeFieldPolynomial();
            this.fields = new Vector();
            this.matrices = new Vector();
            return;
        }
        throw new RuntimeException("\nThe type of this field is " + this.mType);
    }

    /* access modifiers changed from: package-private */
    public int getONBLength() {
        return this.mLength;
    }

    /* access modifiers changed from: package-private */
    public int getONBBit() {
        return this.mBit;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nField
    public GF2nElement getRandomRoot(GF2Polynomial polynomial) {
        GF2nPolynomial h;
        int hDegree;
        int gDegree;
        GF2nPolynomial g = new GF2nPolynomial(polynomial, this);
        int gDegree2 = g.getDegree();
        while (gDegree2 > 1) {
            while (true) {
                GF2nElement u = new GF2nONBElement(this, this.random);
                GF2nPolynomial ut = new GF2nPolynomial(2, GF2nONBElement.ZERO(this));
                ut.set(1, u);
                GF2nPolynomial c = new GF2nPolynomial(ut);
                for (int i = 1; i <= this.mDegree - 1; i++) {
                    c = c.multiplyAndReduce(c, g).add(ut);
                }
                h = c.gcd(g);
                hDegree = h.getDegree();
                gDegree = g.getDegree();
                if (!(hDegree == 0 || hDegree == gDegree)) {
                    break;
                }
            }
            if ((hDegree << 1) > gDegree) {
                g = g.quotient(h);
            } else {
                g = new GF2nPolynomial(h);
            }
            gDegree2 = g.getDegree();
        }
        return g.at(0);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nField
    public void computeCOBMatrix(GF2nField B1) {
        GF2nElement u;
        if (this.mDegree != B1.mDegree) {
            throw new IllegalArgumentException("GF2nField.computeCOBMatrix: B1 has a different degree and thus cannot be coverted to!");
        }
        GF2Polynomial[] COBMatrix = new GF2Polynomial[this.mDegree];
        for (int i = 0; i < this.mDegree; i++) {
            COBMatrix[i] = new GF2Polynomial(this.mDegree);
        }
        do {
            u = B1.getRandomRoot(this.fieldPolynomial);
        } while (u.isZero());
        GF2nElement[] gamma = new GF2nPolynomialElement[this.mDegree];
        gamma[0] = (GF2nElement) u.clone();
        for (int i2 = 1; i2 < this.mDegree; i2++) {
            gamma[i2] = gamma[i2 - 1].square();
        }
        for (int i3 = 0; i3 < this.mDegree; i3++) {
            for (int j = 0; j < this.mDegree; j++) {
                if (gamma[i3].testBit(j)) {
                    COBMatrix[(this.mDegree - j) - 1].setBit((this.mDegree - i3) - 1);
                }
            }
        }
        this.fields.addElement(B1);
        this.matrices.addElement(COBMatrix);
        B1.fields.addElement(this);
        B1.matrices.addElement(invertMatrix(COBMatrix));
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2nField
    public void computeFieldPolynomial() {
        if (this.mType == 1) {
            this.fieldPolynomial = new GF2Polynomial(this.mDegree + 1, "ALL");
        } else if (this.mType == 2) {
            GF2Polynomial q = new GF2Polynomial(this.mDegree + 1, "ONE");
            GF2Polynomial p = new GF2Polynomial(this.mDegree + 1, "X");
            p.addToThis(q);
            for (int i = 1; i < this.mDegree; i++) {
                q = p;
                p = q.shiftLeft();
                p.addToThis(q);
            }
            this.fieldPolynomial = p;
        }
    }

    /* access modifiers changed from: package-private */
    public int[][] invMatrix(int[][] a) {
        int[][] iArr = (int[][]) Array.newInstance(Integer.TYPE, this.mDegree, this.mDegree);
        int[][] inv = (int[][]) Array.newInstance(Integer.TYPE, this.mDegree, this.mDegree);
        for (int i = 0; i < this.mDegree; i++) {
            inv[i][i] = 1;
        }
        for (int i2 = 0; i2 < this.mDegree; i2++) {
            for (int j = i2; j < this.mDegree; j++) {
                a[(this.mDegree - 1) - i2][j] = a[i2][i2];
            }
        }
        return null;
    }

    private void computeType() throws RuntimeException {
        if ((this.mDegree & 7) == 0) {
            throw new RuntimeException("The extension degree is divisible by 8!");
        }
        this.mType = 1;
        int d = 0;
        while (d != 1) {
            int s = (this.mType * this.mDegree) + 1;
            if (IntegerFunctions.isPrime(s)) {
                d = IntegerFunctions.gcd((this.mType * this.mDegree) / IntegerFunctions.order(2, s), this.mDegree);
            }
            this.mType++;
        }
        this.mType--;
        if (this.mType == 1) {
            int s2 = (this.mDegree << 1) + 1;
            if (IntegerFunctions.isPrime(s2)) {
                if (IntegerFunctions.gcd((this.mDegree << 1) / IntegerFunctions.order(2, s2), this.mDegree) == 1) {
                    this.mType++;
                }
            }
        }
    }

    private void computeMultMatrix() {
        int u;
        if ((this.mType & 7) != 0) {
            int p = (this.mType * this.mDegree) + 1;
            int[] F = new int[p];
            if (this.mType == 1) {
                u = 1;
            } else if (this.mType == 2) {
                u = p - 1;
            } else {
                u = elementOfOrder(this.mType, p);
            }
            int w = 1;
            for (int j = 0; j < this.mType; j++) {
                int n = w;
                for (int i = 0; i < this.mDegree; i++) {
                    F[n] = i;
                    n = (n << 1) % p;
                    if (n < 0) {
                        n += p;
                    }
                }
                w = (u * w) % p;
                if (w < 0) {
                    w += p;
                }
            }
            if (this.mType == 1) {
                for (int k = 1; k < p - 1; k++) {
                    if (this.mMult[F[k + 1]][0] == -1) {
                        this.mMult[F[k + 1]][0] = F[p - k];
                    } else {
                        this.mMult[F[k + 1]][1] = F[p - k];
                    }
                }
                int m_2 = this.mDegree >> 1;
                for (int k2 = 1; k2 <= m_2; k2++) {
                    if (this.mMult[k2 - 1][0] == -1) {
                        this.mMult[k2 - 1][0] = (m_2 + k2) - 1;
                    } else {
                        this.mMult[k2 - 1][1] = (m_2 + k2) - 1;
                    }
                    if (this.mMult[(m_2 + k2) - 1][0] == -1) {
                        this.mMult[(m_2 + k2) - 1][0] = k2 - 1;
                    } else {
                        this.mMult[(m_2 + k2) - 1][1] = k2 - 1;
                    }
                }
            } else if (this.mType == 2) {
                for (int k3 = 1; k3 < p - 1; k3++) {
                    if (this.mMult[F[k3 + 1]][0] == -1) {
                        this.mMult[F[k3 + 1]][0] = F[p - k3];
                    } else {
                        this.mMult[F[k3 + 1]][1] = F[p - k3];
                    }
                }
            } else {
                throw new RuntimeException("only type 1 or type 2 implemented");
            }
        } else {
            throw new RuntimeException("bisher nur fuer Gausssche Normalbasen implementiert");
        }
    }

    private int elementOfOrder(int k, int p) {
        Random random = new Random();
        int m = 0;
        while (m == 0) {
            m = random.nextInt() % (p - 1);
            if (m < 0) {
                m += p - 1;
            }
        }
        int l = IntegerFunctions.order(m, p);
        while (true) {
            if (l % k == 0 && l != 0) {
                break;
            }
            while (m == 0) {
                m = random.nextInt() % (p - 1);
                if (m < 0) {
                    m += p - 1;
                }
            }
            l = IntegerFunctions.order(m, p);
        }
        int r = m;
        for (int i = 2; i <= k / l; i++) {
            r *= m;
        }
        return r;
    }
}
