package com.mi.car.jsse.easysec.pqc.math.linearalgebra;

import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;

public class Permutation {
    private int[] perm;

    public Permutation(int n) {
        if (n <= 0) {
            throw new IllegalArgumentException("invalid length");
        }
        this.perm = new int[n];
        for (int i = n - 1; i >= 0; i--) {
            this.perm[i] = i;
        }
    }

    public Permutation(int[] perm2) {
        if (!isPermutation(perm2)) {
            throw new IllegalArgumentException("array is not a permutation vector");
        }
        this.perm = IntUtils.clone(perm2);
    }

    public Permutation(byte[] enc) {
        if (enc.length <= 4) {
            throw new IllegalArgumentException("invalid encoding");
        }
        int n = LittleEndianConversions.OS2IP(enc, 0);
        int size = IntegerFunctions.ceilLog256(n - 1);
        if (enc.length != (n * size) + 4) {
            throw new IllegalArgumentException("invalid encoding");
        }
        this.perm = new int[n];
        for (int i = 0; i < n; i++) {
            this.perm[i] = LittleEndianConversions.OS2IP(enc, (i * size) + 4, size);
        }
        if (!isPermutation(this.perm)) {
            throw new IllegalArgumentException("invalid encoding");
        }
    }

    public Permutation(int n, SecureRandom sr) {
        if (n <= 0) {
            throw new IllegalArgumentException("invalid length");
        }
        this.perm = new int[n];
        int[] help = new int[n];
        for (int i = 0; i < n; i++) {
            help[i] = i;
        }
        int k = n;
        for (int j = 0; j < n; j++) {
            int i2 = RandUtils.nextInt(sr, k);
            k--;
            this.perm[j] = help[i2];
            help[i2] = help[k];
        }
    }

    public byte[] getEncoded() {
        int n = this.perm.length;
        int size = IntegerFunctions.ceilLog256(n - 1);
        byte[] result = new byte[((n * size) + 4)];
        LittleEndianConversions.I2OSP(n, result, 0);
        for (int i = 0; i < n; i++) {
            LittleEndianConversions.I2OSP(this.perm[i], result, (i * size) + 4, size);
        }
        return result;
    }

    public int[] getVector() {
        return IntUtils.clone(this.perm);
    }

    public Permutation computeInverse() {
        Permutation result = new Permutation(this.perm.length);
        for (int i = this.perm.length - 1; i >= 0; i--) {
            result.perm[this.perm[i]] = i;
        }
        return result;
    }

    public Permutation rightMultiply(Permutation p) {
        if (p.perm.length != this.perm.length) {
            throw new IllegalArgumentException("length mismatch");
        }
        Permutation result = new Permutation(this.perm.length);
        for (int i = this.perm.length - 1; i >= 0; i--) {
            result.perm[i] = this.perm[p.perm[i]];
        }
        return result;
    }

    public boolean equals(Object other) {
        if (!(other instanceof Permutation)) {
            return false;
        }
        return IntUtils.equals(this.perm, ((Permutation) other).perm);
    }

    public String toString() {
        String result = "[" + this.perm[0];
        for (int i = 1; i < this.perm.length; i++) {
            result = result + ", " + this.perm[i];
        }
        return result + "]";
    }

    public int hashCode() {
        return Arrays.hashCode(this.perm);
    }

    private boolean isPermutation(int[] perm2) {
        int n = perm2.length;
        boolean[] onlyOnce = new boolean[n];
        for (int i = 0; i < n; i++) {
            if (perm2[i] < 0 || perm2[i] >= n || onlyOnce[perm2[i]]) {
                return false;
            }
            onlyOnce[perm2[i]] = true;
        }
        return true;
    }
}
