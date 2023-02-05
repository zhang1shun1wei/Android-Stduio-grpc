package com.mi.car.jsse.easysec.pqc.math.linearalgebra;

import java.security.SecureRandom;
import java.util.Vector;

public class GF2nPolynomialField extends GF2nField {
    GF2Polynomial[] squaringMatrix;
    private boolean isTrinomial = false;
    private boolean isPentanomial = false;
    private int tc;
    private int[] pc = new int[3];

    public GF2nPolynomialField(int deg, SecureRandom random) {
        super(random);
        if (deg < 3) {
            throw new IllegalArgumentException("k must be at least 3");
        } else {
            this.mDegree = deg;
            this.computeFieldPolynomial();
            this.computeSquaringMatrix();
            this.fields = new Vector();
            this.matrices = new Vector();
        }
    }

    public GF2nPolynomialField(int deg, SecureRandom random, boolean file) {
        super(random);
        if (deg < 3) {
            throw new IllegalArgumentException("k must be at least 3");
        } else {
            this.mDegree = deg;
            if (file) {
                this.computeFieldPolynomial();
            } else {
                this.computeFieldPolynomial2();
            }

            this.computeSquaringMatrix();
            this.fields = new Vector();
            this.matrices = new Vector();
        }
    }

    public GF2nPolynomialField(int deg, SecureRandom random, GF2Polynomial polynomial) throws RuntimeException {
        super(random);
        if (deg < 3) {
            throw new IllegalArgumentException("degree must be at least 3");
        } else if (polynomial.getLength() != deg + 1) {
            throw new RuntimeException();
        } else if (!polynomial.isIrreducible()) {
            throw new RuntimeException();
        } else {
            this.mDegree = deg;
            this.fieldPolynomial = polynomial;
            this.computeSquaringMatrix();
            int k = 2;

            for(int j = 1; j < this.fieldPolynomial.getLength() - 1; ++j) {
                if (this.fieldPolynomial.testBit(j)) {
                    ++k;
                    if (k == 3) {
                        this.tc = j;
                    }

                    if (k <= 5) {
                        this.pc[k - 3] = j;
                    }
                }
            }

            if (k == 3) {
                this.isTrinomial = true;
            }

            if (k == 5) {
                this.isPentanomial = true;
            }

            this.fields = new Vector();
            this.matrices = new Vector();
        }
    }

    public boolean isTrinomial() {
        return this.isTrinomial;
    }

    public boolean isPentanomial() {
        return this.isPentanomial;
    }

    public int getTc() throws RuntimeException {
        if (!this.isTrinomial) {
            throw new RuntimeException();
        } else {
            return this.tc;
        }
    }

    public int[] getPc() throws RuntimeException {
        if (!this.isPentanomial) {
            throw new RuntimeException();
        } else {
            int[] result = new int[3];
            System.arraycopy(this.pc, 0, result, 0, 3);
            return result;
        }
    }

    public GF2Polynomial getSquaringVector(int i) {
        return new GF2Polynomial(this.squaringMatrix[i]);
    }

    public GF2nElement getRandomRoot(GF2Polynomial polynomial) {
        GF2nPolynomial g = new GF2nPolynomial(polynomial, this);

        for(int gDegree = g.getDegree(); gDegree > 1; gDegree = g.getDegree()) {
            GF2nPolynomial h;
            int hDegree;
            do {
                GF2nElement u = new GF2nPolynomialElement(this, this.random);
                GF2nPolynomial ut = new GF2nPolynomial(2, GF2nPolynomialElement.ZERO(this));
                ut.set(1, u);
                GF2nPolynomial c = new GF2nPolynomial(ut);

                for(int i = 1; i <= this.mDegree - 1; ++i) {
                    c = c.multiplyAndReduce(c, g);
                    c = c.add(ut);
                }

                h = c.gcd(g);
                hDegree = h.getDegree();
                gDegree = g.getDegree();
            } while(hDegree == 0 || hDegree == gDegree);

            if (hDegree << 1 > gDegree) {
                g = g.quotient(h);
            } else {
                g = new GF2nPolynomial(h);
            }
        }

        return g.at(0);
    }

    public void computeCOBMatrix(GF2nField B1) {
        if (this.mDegree != B1.mDegree) {
            throw new IllegalArgumentException("GF2nPolynomialField.computeCOBMatrix: B1 has a different degree and thus cannot be coverted to!");
        } else if (B1 instanceof GF2nONBField) {
            B1.computeCOBMatrix(this);
        } else {
            GF2Polynomial[] COBMatrix = new GF2Polynomial[this.mDegree];

            int i;
            for(i = 0; i < this.mDegree; ++i) {
                COBMatrix[i] = new GF2Polynomial(this.mDegree);
            }

            GF2nElement u;
            do {
                u = B1.getRandomRoot(this.fieldPolynomial);
            } while(u.isZero());

            Object gamma;
            if (u instanceof GF2nONBElement) {
                gamma = new GF2nONBElement[this.mDegree];
                ((Object[])gamma)[this.mDegree - 1] = GF2nONBElement.ONE((GF2nONBField)B1);
            } else {
                gamma = new GF2nPolynomialElement[this.mDegree];
                ((Object[])gamma)[this.mDegree - 1] = GF2nPolynomialElement.ONE((GF2nPolynomialField)B1);
            }

            ((Object[])gamma)[this.mDegree - 2] = u;

            for(i = this.mDegree - 3; i >= 0; --i) {
                ((Object[])gamma)[i] = (GF2nElement)((GF2nElement)((Object[])gamma)[i + 1]).multiply(u);
            }

            int j;
            if (B1 instanceof GF2nONBField) {
                for(i = 0; i < this.mDegree; ++i) {
                    for(j = 0; j < this.mDegree; ++j) {
                        if (((GF2nElement)((Object[])gamma)[i]).testBit(this.mDegree - j - 1)) {
                            COBMatrix[this.mDegree - j - 1].setBit(this.mDegree - i - 1);
                        }
                    }
                }
            } else {
                for(i = 0; i < this.mDegree; ++i) {
                    for(j = 0; j < this.mDegree; ++j) {
                        if (((GF2nElement)((Object[])gamma)[i]).testBit(j)) {
                            COBMatrix[this.mDegree - j - 1].setBit(this.mDegree - i - 1);
                        }
                    }
                }
            }

            this.fields.addElement(B1);
            this.matrices.addElement(COBMatrix);
            B1.fields.addElement(this);
            B1.matrices.addElement(this.invertMatrix(COBMatrix));
        }
    }

    private void computeSquaringMatrix() {
        GF2Polynomial[] d = new GF2Polynomial[this.mDegree - 1];
        this.squaringMatrix = new GF2Polynomial[this.mDegree];

        int i;
        for(i = 0; i < this.squaringMatrix.length; ++i) {
            this.squaringMatrix[i] = new GF2Polynomial(this.mDegree, "ZERO");
        }

        for(i = 0; i < this.mDegree - 1; ++i) {
            d[i] = (new GF2Polynomial(1, "ONE")).shiftLeft(this.mDegree + i).remainder(this.fieldPolynomial);
        }

        for(i = 1; i <= Math.abs(this.mDegree >> 1); ++i) {
            for(int j = 1; j <= this.mDegree; ++j) {
                if (d[this.mDegree - (i << 1)].testBit(this.mDegree - j)) {
                    this.squaringMatrix[j - 1].setBit(this.mDegree - i);
                }
            }
        }

        for(i = Math.abs(this.mDegree >> 1) + 1; i <= this.mDegree; ++i) {
            this.squaringMatrix[(i << 1) - this.mDegree - 1].setBit(this.mDegree - i);
        }

    }

    public void computeFieldPolynomial() {
        if (!this.testTrinomials()) {
            if (!this.testPentanomials()) {
                this.testRandom();
            }
        }
    }

    protected void computeFieldPolynomial2() {
        if (!this.testTrinomials()) {
            if (!this.testPentanomials()) {
                this.testRandom();
            }
        }
    }

    private boolean testTrinomials() {
        boolean done = false;
        int l = 0;
        this.fieldPolynomial = new GF2Polynomial(this.mDegree + 1);
        this.fieldPolynomial.setBit(0);
        this.fieldPolynomial.setBit(this.mDegree);

        for(int i = 1; i < this.mDegree && !done; ++i) {
            this.fieldPolynomial.setBit(i);
            done = this.fieldPolynomial.isIrreducible();
            ++l;
            if (done) {
                this.isTrinomial = true;
                this.tc = i;
                return done;
            }

            this.fieldPolynomial.resetBit(i);
            done = this.fieldPolynomial.isIrreducible();
        }

        return done;
    }

    private boolean testPentanomials() {
        boolean done = false;
        int l = 0;
        this.fieldPolynomial = new GF2Polynomial(this.mDegree + 1);
        this.fieldPolynomial.setBit(0);
        this.fieldPolynomial.setBit(this.mDegree);

        for(int i = 1; i <= this.mDegree - 3 && !done; ++i) {
            this.fieldPolynomial.setBit(i);

            for(int j = i + 1; j <= this.mDegree - 2 && !done; ++j) {
                this.fieldPolynomial.setBit(j);

                for(int k = j + 1; k <= this.mDegree - 1 && !done; ++k) {
                    this.fieldPolynomial.setBit(k);
                    if ((this.mDegree & 1) != 0 | (i & 1) != 0 | (j & 1) != 0 | (k & 1) != 0) {
                        done = this.fieldPolynomial.isIrreducible();
                        ++l;
                        if (done) {
                            this.isPentanomial = true;
                            this.pc[0] = i;
                            this.pc[1] = j;
                            this.pc[2] = k;
                            return done;
                        }
                    }

                    this.fieldPolynomial.resetBit(k);
                }

                this.fieldPolynomial.resetBit(j);
            }

            this.fieldPolynomial.resetBit(i);
        }

        return done;
    }

    private boolean testRandom() {
        boolean done = false;
        this.fieldPolynomial = new GF2Polynomial(this.mDegree + 1);
        int var1 = 0;

        do {
            if (done) {
                return done;
            }

            ++var1;
            this.fieldPolynomial.randomize();
            this.fieldPolynomial.setBit(this.mDegree);
            this.fieldPolynomial.setBit(0);
        } while(!this.fieldPolynomial.isIrreducible());

        done = true;
        return done;
    }
}
