package com.mi.car.jsse.easysec.pqc.crypto.saber;

import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;

class Poly {
    private static final int KARATSUBA_N = 64;
    private static int SCHB_N = 16;
    private final int N_RES;
    private final int N_SB;
    private final int N_SB_RES;
    private final int SABER_N;
    private final int SABER_L;
    private final SABEREngine engine;
    private final Utils utils;

    public Poly(SABEREngine engine) {
        this.engine = engine;
        this.SABER_L = engine.getSABER_L();
        this.SABER_N = engine.getSABER_N();
        this.N_RES = this.SABER_N << 1;
        this.N_SB = this.SABER_N >> 2;
        this.N_SB_RES = 2 * this.N_SB - 1;
        this.utils = engine.getUtils();
    }

    public void GenMatrix(short[][][] A, byte[] seed) {
        byte[] buf = new byte[this.SABER_L * this.engine.getSABER_POLYVECBYTES()];
        Xof digest = new SHAKEDigest(128);
        digest.update(seed, 0, this.engine.getSABER_SEEDBYTES());
        digest.doFinal(buf, 0, buf.length);

        for(int i = 0; i < this.SABER_L; ++i) {
            this.utils.BS2POLVECq(buf, i * this.engine.getSABER_POLYVECBYTES(), A[i]);
        }

    }

    public void GenSecret(short[][] s, byte[] seed) {
        byte[] buf = new byte[this.SABER_L * this.engine.getSABER_POLYCOINBYTES()];
        Xof digest = new SHAKEDigest(128);
        digest.update(seed, 0, this.engine.getSABER_NOISE_SEEDBYTES());
        digest.doFinal(buf, 0, buf.length);

        for(int i = 0; i < this.SABER_L; ++i) {
            this.cbd(s[i], buf, i * this.engine.getSABER_POLYCOINBYTES());
        }

    }

    private long load_littleendian(byte[] x, int offset, int bytes) {
        long r = (long)(x[offset + 0] & 255);

        for(int i = 1; i < bytes; ++i) {
            r |= (long)(x[offset + i] & 255) << 8 * i;
        }

        return r;
    }

    private void cbd(short[] s, byte[] buf, int offset) {
        int[] a = new int[4];
        int[] b = new int[4];
        int i;
        int j;
        int t;
        int d;
        if (this.engine.getSABER_MU() == 6) {
            for(i = 0; i < this.SABER_N / 4; ++i) {
                t = (int)this.load_littleendian(buf, offset + 3 * i, 3);
                d = 0;

                for(j = 0; j < 3; ++j) {
                    d += t >> j & 2396745;
                }

                a[0] = d & 7;
                b[0] = d >>> 3 & 7;
                a[1] = d >>> 6 & 7;
                b[1] = d >>> 9 & 7;
                a[2] = d >>> 12 & 7;
                b[2] = d >>> 15 & 7;
                a[3] = d >>> 18 & 7;
                b[3] = d >>> 21;
                s[4 * i + 0] = (short)(a[0] - b[0]);
                s[4 * i + 1] = (short)(a[1] - b[1]);
                s[4 * i + 2] = (short)(a[2] - b[2]);
                s[4 * i + 3] = (short)(a[3] - b[3]);
            }
        } else if (this.engine.getSABER_MU() == 8) {
            for(i = 0; i < this.SABER_N / 4; ++i) {
                t = (int)this.load_littleendian(buf, offset + 4 * i, 4);
                d = 0;

                for(j = 0; j < 4; ++j) {
                    d += t >>> j & 286331153;
                }

                a[0] = d & 15;
                b[0] = d >>> 4 & 15;
                a[1] = d >>> 8 & 15;
                b[1] = d >>> 12 & 15;
                a[2] = d >>> 16 & 15;
                b[2] = d >>> 20 & 15;
                a[3] = d >>> 24 & 15;
                b[3] = d >>> 28;
                s[4 * i + 0] = (short)(a[0] - b[0]);
                s[4 * i + 1] = (short)(a[1] - b[1]);
                s[4 * i + 2] = (short)(a[2] - b[2]);
                s[4 * i + 3] = (short)(a[3] - b[3]);
            }
        } else if (this.engine.getSABER_MU() == 10) {
            for(i = 0; i < this.SABER_N / 4; ++i) {
                long t1 = this.load_littleendian(buf, offset + 5 * i, 5);
                long d1 = 0L;

                for(j = 0; j < 5; ++j) {
                    d1 += t1 >>> j & 35468117025L;
                }

                a[0] = (int)(d1 & 31L);
                b[0] = (int)(d1 >>> 5 & 31L);
                a[1] = (int)(d1 >>> 10 & 31L);
                b[1] = (int)(d1 >>> 15 & 31L);
                a[2] = (int)(d1 >>> 20 & 31L);
                b[2] = (int)(d1 >>> 25 & 31L);
                a[3] = (int)(d1 >>> 30 & 31L);
                b[3] = (int)(d1 >>> 35);
                s[4 * i + 0] = (short)(a[0] - b[0]);
                s[4 * i + 1] = (short)(a[1] - b[1]);
                s[4 * i + 2] = (short)(a[2] - b[2]);
                s[4 * i + 3] = (short)(a[3] - b[3]);
            }
        }

    }

    private short OVERFLOWING_MUL(int x, int y) {
        return (short)(x * y);
    }

    private void karatsuba_simple(int[] a_1, int[] b_1, int[] result_final) {
        int[] d01 = new int[31];
        int[] d0123 = new int[31];
        int[] d23 = new int[31];
        int[] result_d01 = new int[63];

        int i;
        for(i = 0; i < 16; ++i) {
            int acc1 = a_1[i];
            int acc2 = a_1[i + 16];
            int acc3 = a_1[i + 32];
            int acc4 = a_1[i + 48];

            for(int j = 0; j < 16; ++j) {
                int acc5 = b_1[j];
                int acc6 = b_1[j + 16];
                result_final[i + j + 0] += this.OVERFLOWING_MUL(acc1, acc5);
                result_final[i + j + 32] += this.OVERFLOWING_MUL(acc2, acc6);
                int acc7 = acc5 + acc6;
                int acc8 = acc1 + acc2;
                d01[i + j] = (int)((long)d01[i + j] + (long)acc7 * (long)acc8);
                acc7 = b_1[j + 32];
                acc8 = b_1[j + 48];
                result_final[i + j + 64] += this.OVERFLOWING_MUL(acc7, acc3);
                result_final[i + j + 96] += this.OVERFLOWING_MUL(acc8, acc4);
                int acc9 = acc3 + acc4;
                int acc10 = acc7 + acc8;
                d23[i + j] += this.OVERFLOWING_MUL(acc9, acc10);
                acc5 += acc7;
                acc7 = acc1 + acc3;
                result_d01[i + j + 0] += this.OVERFLOWING_MUL(acc5, acc7);
                acc6 += acc8;
                acc8 = acc2 + acc4;
                result_d01[i + j + 32] += this.OVERFLOWING_MUL(acc6, acc8);
                acc5 += acc6;
                acc7 += acc8;
                d0123[i + j] += this.OVERFLOWING_MUL(acc5, acc7);
            }
        }

        for(i = 0; i < 31; ++i) {
            d0123[i] = d0123[i] - result_d01[i + 0] - result_d01[i + 32];
            d01[i] = d01[i] - result_final[i + 0] - result_final[i + 32];
            d23[i] = d23[i] - result_final[i + 64] - result_final[i + 96];
        }

        for(i = 0; i < 31; ++i) {
            result_d01[i + 16] += d0123[i];
            result_final[i + 16] += d01[i];
            result_final[i + 80] += d23[i];
        }

        for(i = 0; i < 63; ++i) {
            result_d01[i] = result_d01[i] - result_final[i] - result_final[i + 64];
        }

        for(i = 0; i < 63; ++i) {
            result_final[i + 32] += result_d01[i];
        }

    }

    private void toom_cook_4way(short[] a1, short[] b1, short[] result) {
        int inv3 = '1';
        int inv9 = '1';
        int inv15 = '\ueeef';
        int[] aw1 = new int[this.N_SB];
        int[] aw2 = new int[this.N_SB];
        int[] aw3 = new int[this.N_SB];
        int[] aw4 = new int[this.N_SB];
        int[] aw5 = new int[this.N_SB];
        int[] aw6 = new int[this.N_SB];
        int[] aw7 = new int[this.N_SB];
        int[] bw1 = new int[this.N_SB];
        int[] bw2 = new int[this.N_SB];
        int[] bw3 = new int[this.N_SB];
        int[] bw4 = new int[this.N_SB];
        int[] bw5 = new int[this.N_SB];
        int[] bw6 = new int[this.N_SB];
        int[] bw7 = new int[this.N_SB];
        int[] w1 = new int[this.N_SB_RES];
        int[] w2 = new int[this.N_SB_RES];
        int[] w3 = new int[this.N_SB_RES];
        int[] w4 = new int[this.N_SB_RES];
        int[] w5 = new int[this.N_SB_RES];
        int[] w6 = new int[this.N_SB_RES];
        int[] w7 = new int[this.N_SB_RES];
        short[] C = result;

        int r0;
        int r1;
        int r2;
        int r3;
        int j;
        for(j = 0; j < this.N_SB; ++j) {
            r0 = a1[j];
            r1 = a1[j + this.N_SB];
            r2 = a1[j + this.N_SB * 2];
            r3 = a1[j + this.N_SB * 3];
            int r4 = (short)(r0 + r2);
            int r5 = (short)(r1 + r3);
            int r6 = (short)(r4 + r5);
            int r7 = (short)(r4 - r5);
            aw3[j] = r6;
            aw4[j] = r7;
            r4 = (short)((r0 << 2) + r2 << 1);
            r5 = (short)((r1 << 2) + r3);
            r6 = (short)(r4 + r5);
            r7 = (short)(r4 - r5);
            aw5[j] = r6;
            aw6[j] = r7;
            r4 = (short)((r3 << 3) + (r2 << 2) + (r1 << 1) + r0);
            aw2[j] = r4;
            aw7[j] = r0;
            aw1[j] = r3;
        }

        int r4;
        int r5;
        int r6;
        for(j = 0; j < this.N_SB; ++j) {
            r0 = b1[j];
            r1 = b1[j + this.N_SB];
            r2 = b1[j + this.N_SB * 2];
            r3 = b1[j + this.N_SB * 3];
            r4 = r0 + r2;
            r5 = r1 + r3;
            r6 = r4 + r5;
            int r7 = r4 - r5;
            bw3[j] = r6;
            bw4[j] = r7;
            r4 = (r0 << 2) + r2 << 1;
            r5 = (r1 << 2) + r3;
            r6 = r4 + r5;
            r7 = r4 - r5;
            bw5[j] = r6;
            bw6[j] = r7;
            r4 = (r3 << 3) + (r2 << 2) + (r1 << 1) + r0;
            bw2[j] = r4;
            bw7[j] = r0;
            bw1[j] = r3;
        }

        this.karatsuba_simple(aw1, bw1, w1);
        this.karatsuba_simple(aw2, bw2, w2);
        this.karatsuba_simple(aw3, bw3, w3);
        this.karatsuba_simple(aw4, bw4, w4);
        this.karatsuba_simple(aw5, bw5, w5);
        this.karatsuba_simple(aw6, bw6, w6);
        this.karatsuba_simple(aw7, bw7, w7);

        for(int i = 0; i < this.N_SB_RES; ++i) {
            r0 = w1[i];
            r1 = w2[i];
            r2 = w3[i];
            r3 = w4[i];
            r4 = w5[i];
            r5 = w6[i];
            r6 = w7[i];
            r1 += r4;
            r5 -= r4;
            r3 = (r3 & '\uffff') - (r2 & '\uffff') >>> 1;
            r4 -= r0;
            r4 -= r6 << 6;
            r4 = (r4 << 1) + r5;
            r2 += r3;
            r1 = r1 - (r2 << 6) - r2;
            r2 -= r6;
            r2 -= r0;
            r1 += 45 * r2;
            r4 = ((r4 & '\uffff') - (r2 << 3)) * inv3 >> 3;
            r5 += r1;
            r1 = ((r1 & '\uffff') + ((r3 & '\uffff') << 4)) * inv9 >> 1;
            r3 = -(r3 + r1);
            r5 = (30 * (r1 & '\uffff') - (r5 & '\uffff')) * inv15 >> 2;
            r2 -= r4;
            r1 -= r5;
            C[i] = (short)(C[i] + (r6 & '\uffff'));
            C[i + 64] = (short)(C[i + 64] + (r5 & '\uffff'));
            C[i + 128] = (short)(C[i + 128] + (r4 & '\uffff'));
            C[i + 192] = (short)(C[i + 192] + (r3 & '\uffff'));
            C[i + 256] = (short)(C[i + 256] + (r2 & '\uffff'));
            C[i + 320] = (short)(C[i + 320] + (r1 & '\uffff'));
            C[i + 384] = (short)(C[i + 384] + (r0 & '\uffff'));
        }

    }

    private void poly_mul_acc(short[] a, short[] b, short[] res) {
        short[] c = new short[2 * this.SABER_N];
        this.toom_cook_4way(a, b, c);

        for(int i = this.SABER_N; i < 2 * this.SABER_N; ++i) {
            int var10001 = i - this.SABER_N;
            res[var10001] = (short)(res[var10001] + (c[i - this.SABER_N] - c[i]));
        }

    }

    public void MatrixVectorMul(short[][][] A, short[][] s, short[][] res, int transpose) {
        for(int i = 0; i < this.SABER_L; ++i) {
            for(int j = 0; j < this.SABER_L; ++j) {
                if (transpose == 1) {
                    this.poly_mul_acc(A[j][i], s[j], res[i]);
                } else {
                    this.poly_mul_acc(A[i][j], s[j], res[i]);
                }
            }
        }

    }

    public void InnerProd(short[][] b, short[][] s, short[] res) {
        for(int j = 0; j < this.SABER_L; ++j) {
            this.poly_mul_acc(b[j], s[j], res);
        }

    }
}
