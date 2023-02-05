package com.mi.car.jsse.easysec.pqc.crypto.cmce;

abstract class BENES {
    protected final int GFBITS;
    protected final int SYS_N;
    protected final int SYS_T;

    /* access modifiers changed from: protected */
    public abstract void support_gen(short[] sArr, byte[] bArr);

    public BENES(int n, int t, int m) {
        this.SYS_N = n;
        this.SYS_T = t;
        this.GFBITS = m;
    }

    static void transpose_64x64(long[] out, long[] in) {
        long[][] masks = {new long[]{6148914691236517205L, -6148914691236517206L}, new long[]{3689348814741910323L, -3689348814741910324L}, new long[]{1085102592571150095L, -1085102592571150096L}, new long[]{71777214294589695L, -71777214294589696L}, new long[]{281470681808895L, -281470681808896L}, new long[]{4294967295L, -4294967296L}};
        for (int i = 0; i < 64; i++) {
            out[i] = in[i];
        }
        for (int d = 5; d >= 0; d--) {
            int s = 1 << d;
            for (int i2 = 0; i2 < 64; i2 += s * 2) {
                for (int j = i2; j < i2 + s; j++) {
                    out[j + 0] = (out[j] & masks[d][0]) | ((out[j + s] & masks[d][0]) << s);
                    out[j + s] = ((out[j] & masks[d][1]) >>> s) | (out[j + s] & masks[d][1]);
                }
            }
        }
    }

    static void transpose_64x64(long[] out, long[] in, int offset) {
        long[][] masks = {new long[]{6148914691236517205L, -6148914691236517206L}, new long[]{3689348814741910323L, -3689348814741910324L}, new long[]{1085102592571150095L, -1085102592571150096L}, new long[]{71777214294589695L, -71777214294589696L}, new long[]{281470681808895L, -281470681808896L}, new long[]{4294967295L, -4294967296L}};
        for (int i = 0; i < 64; i++) {
            out[i + offset] = in[i + offset];
        }
        for (int d = 5; d >= 0; d--) {
            int s = 1 << d;
            for (int i2 = 0; i2 < 64; i2 += s * 2) {
                for (int j = i2; j < i2 + s; j++) {
                    out[j + 0 + offset] = (out[j + offset] & masks[d][0]) | ((out[(j + s) + offset] & masks[d][0]) << s);
                    out[j + s + offset] = ((out[j + offset] & masks[d][1]) >>> s) | (out[j + s + offset] & masks[d][1]);
                }
            }
        }
    }
}
