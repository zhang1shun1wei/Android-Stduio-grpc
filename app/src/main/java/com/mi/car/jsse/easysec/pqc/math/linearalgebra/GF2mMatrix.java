package com.mi.car.jsse.easysec.pqc.math.linearalgebra;

import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import java.lang.reflect.Array;

public class GF2mMatrix extends Matrix {
    protected GF2mField field;
    protected int[][] matrix;

    public GF2mMatrix(GF2mField field2, byte[] enc) {
        this.field = field2;
        int d = 8;
        int count = 1;
        while (field2.getDegree() > d) {
            count++;
            d += 8;
        }
        if (enc.length < 5) {
            throw new IllegalArgumentException(" Error: given array is not encoded matrix over GF(2^m)");
        }
        this.numRows = ((((enc[3] & 255) << 24) ^ ((enc[2] & 255) << 16)) ^ ((enc[1] & 255) << 8)) ^ (enc[0] & 255);
        int n = count * this.numRows;
        if (this.numRows <= 0 || (enc.length - 4) % n != 0) {
            throw new IllegalArgumentException(" Error: given array is not encoded matrix over GF(2^m)");
        }
        this.numColumns = (enc.length - 4) / n;
        this.matrix = (int[][]) Array.newInstance(Integer.TYPE, this.numRows, this.numColumns);
        int count2 = 4;
        for (int i = 0; i < this.numRows; i++) {
            int j = 0;
            while (j < this.numColumns) {
                int jj = 0;
                int count3 = count2;
                while (jj < d) {
                    int[] iArr = this.matrix[i];
                    iArr[j] = iArr[j] ^ ((enc[count3] & 255) << jj);
                    jj += 8;
                    count3++;
                }
                if (!this.field.isElementOfThisField(this.matrix[i][j])) {
                    throw new IllegalArgumentException(" Error: given array is not encoded matrix over GF(2^m)");
                }
                j++;
                count2 = count3;
            }
        }
    }

    public GF2mMatrix(GF2mMatrix other) {
        this.numRows = other.numRows;
        this.numColumns = other.numColumns;
        this.field = other.field;
        this.matrix = new int[this.numRows][];
        for (int i = 0; i < this.numRows; i++) {
            this.matrix[i] = IntUtils.clone(other.matrix[i]);
        }
    }

    protected GF2mMatrix(GF2mField field2, int[][] matrix2) {
        this.field = field2;
        this.matrix = matrix2;
        this.numRows = matrix2.length;
        this.numColumns = matrix2[0].length;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Matrix
    public byte[] getEncoded() {
        int d = 8;
        int count = 1;
        while (this.field.getDegree() > d) {
            count++;
            d += 8;
        }
        byte[] bf = new byte[((this.numRows * this.numColumns * count) + 4)];
        bf[0] = (byte) (this.numRows & GF2Field.MASK);
        bf[1] = (byte) ((this.numRows >>> 8) & GF2Field.MASK);
        bf[2] = (byte) ((this.numRows >>> 16) & GF2Field.MASK);
        bf[3] = (byte) ((this.numRows >>> 24) & GF2Field.MASK);
        int count2 = 4;
        for (int i = 0; i < this.numRows; i++) {
            int j = 0;
            while (j < this.numColumns) {
                int jj = 0;
                int count3 = count2;
                while (jj < d) {
                    bf[count3] = (byte) (this.matrix[i][j] >>> jj);
                    jj += 8;
                    count3++;
                }
                j++;
                count2 = count3;
            }
        }
        return bf;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Matrix
    public boolean isZero() {
        for (int i = 0; i < this.numRows; i++) {
            for (int j = 0; j < this.numColumns; j++) {
                if (this.matrix[i][j] != 0) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Matrix
    public Matrix computeInverse() {
        int coef;
        if (this.numRows != this.numColumns) {
            throw new ArithmeticException("Matrix is not invertible.");
        }
        int[][] tmpMatrix = (int[][]) Array.newInstance(Integer.TYPE, this.numRows, this.numRows);
        for (int i = this.numRows - 1; i >= 0; i--) {
            tmpMatrix[i] = IntUtils.clone(this.matrix[i]);
        }
        int[][] invMatrix = (int[][]) Array.newInstance(Integer.TYPE, this.numRows, this.numRows);
        for (int i2 = this.numRows - 1; i2 >= 0; i2--) {
            invMatrix[i2][i2] = 1;
        }
        for (int i3 = 0; i3 < this.numRows; i3++) {
            if (tmpMatrix[i3][i3] == 0) {
                boolean foundNonZero = false;
                int j = i3 + 1;
                while (j < this.numRows) {
                    if (tmpMatrix[j][i3] != 0) {
                        foundNonZero = true;
                        swapColumns(tmpMatrix, i3, j);
                        swapColumns(invMatrix, i3, j);
                        j = this.numRows;
                    }
                    j++;
                }
                if (!foundNonZero) {
                    throw new ArithmeticException("Matrix is not invertible.");
                }
            }
            int invCoef = this.field.inverse(tmpMatrix[i3][i3]);
            multRowWithElementThis(tmpMatrix[i3], invCoef);
            multRowWithElementThis(invMatrix[i3], invCoef);
            for (int j2 = 0; j2 < this.numRows; j2++) {
                if (!(j2 == i3 || (coef = tmpMatrix[j2][i3]) == 0)) {
                    int[] tmpRow = multRowWithElement(tmpMatrix[i3], coef);
                    int[] tmpInvRow = multRowWithElement(invMatrix[i3], coef);
                    addToRow(tmpRow, tmpMatrix[j2]);
                    addToRow(tmpInvRow, invMatrix[j2]);
                }
            }
        }
        return new GF2mMatrix(this.field, invMatrix);
    }

    private static void swapColumns(int[][] matrix2, int first, int second) {
        int[] tmp = matrix2[first];
        matrix2[first] = matrix2[second];
        matrix2[second] = tmp;
    }

    private void multRowWithElementThis(int[] row, int element) {
        for (int i = row.length - 1; i >= 0; i--) {
            row[i] = this.field.mult(row[i], element);
        }
    }

    private int[] multRowWithElement(int[] row, int element) {
        int[] result = new int[row.length];
        for (int i = row.length - 1; i >= 0; i--) {
            result[i] = this.field.mult(row[i], element);
        }
        return result;
    }

    private void addToRow(int[] fromRow, int[] toRow) {
        for (int i = toRow.length - 1; i >= 0; i--) {
            toRow[i] = this.field.add(fromRow[i], toRow[i]);
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Matrix
    public Matrix rightMultiply(Matrix a) {
        throw new RuntimeException("Not implemented.");
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Matrix
    public Matrix rightMultiply(Permutation perm) {
        throw new RuntimeException("Not implemented.");
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Matrix
    public Vector leftMultiply(Vector vector) {
        throw new RuntimeException("Not implemented.");
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Matrix
    public Vector rightMultiply(Vector vector) {
        throw new RuntimeException("Not implemented.");
    }

    public boolean equals(Object other) {
        if (other == null || !(other instanceof GF2mMatrix)) {
            return false;
        }
        GF2mMatrix otherMatrix = (GF2mMatrix) other;
        if (!(this.field.equals(otherMatrix.field) && otherMatrix.numRows == this.numColumns && otherMatrix.numColumns == this.numColumns)) {
            return false;
        }
        for (int i = 0; i < this.numRows; i++) {
            for (int j = 0; j < this.numColumns; j++) {
                if (this.matrix[i][j] != otherMatrix.matrix[i][j]) {
                    return false;
                }
            }
        }
        return true;
    }

    public int hashCode() {
        int hash = (((this.field.hashCode() * 31) + this.numRows) * 31) + this.numColumns;
        for (int i = 0; i < this.numRows; i++) {
            for (int j = 0; j < this.numColumns; j++) {
                hash = (hash * 31) + this.matrix[i][j];
            }
        }
        return hash;
    }

    @Override // com.mi.car.jsse.easysec.pqc.math.linearalgebra.Matrix
    public String toString() {
        String str = this.numRows + " x " + this.numColumns + " Matrix over " + this.field.toString() + ": \n";
        for (int i = 0; i < this.numRows; i++) {
            for (int j = 0; j < this.numColumns; j++) {
                str = str + this.field.elementToStr(this.matrix[i][j]) + " : ";
            }
            str = str + "\n";
        }
        return str;
    }
}
