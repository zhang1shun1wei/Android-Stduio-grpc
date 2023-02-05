package com.mi.car.jsse.easysec.pqc.crypto.cmce;

import java.lang.reflect.Array;

class BENES13 extends BENES {
    public BENES13(int n, int t, int m) {
        super(n, t, m);
    }

    static void layer_in(long[] data, long[] bits, int lgs) {
        int bit_ptr = 0;
        int s = 1 << lgs;
        int i = 0;
        while (i < 64) {
            int bit_ptr2 = bit_ptr;
            for (int j = i; j < i + s; j++) {
                int bit_ptr3 = bit_ptr2 + 1;
                long d = (data[j + 0] ^ data[j + s]) & bits[bit_ptr2];
                int i2 = j + 0;
                data[i2] = data[i2] ^ d;
                int i3 = j + s;
                data[i3] = data[i3] ^ d;
                bit_ptr2 = bit_ptr3 + 1;
                long d2 = (data[(j + 64) + 0] ^ data[(j + 64) + s]) & bits[bit_ptr3];
                int i4 = j + 64 + 0;
                data[i4] = data[i4] ^ d2;
                int i5 = j + 64 + s;
                data[i5] = data[i5] ^ d2;
            }
            i += s * 2;
            bit_ptr = bit_ptr2;
        }
    }

    static void layer_ex(long[] data, long[] bits, int lgs) {
        int bit_ptr = 0;
        int s = 1 << lgs;
        int i = 0;
        while (i < 128) {
            for (int j = i; j < i + s; j++) {
                bit_ptr++;
                long d = (data[j + 0] ^ data[j + s]) & bits[bit_ptr];
                int i2 = j + 0;
                data[i2] = data[i2] ^ d;
                int i3 = j + s;
                data[i3] = data[i3] ^ d;
            }
            i += s * 2;
            bit_ptr = bit_ptr;
        }
    }

    /* access modifiers changed from: package-private */
    public void apply_benes(byte[] r, byte[] bits, int rev) {
        int bits_ptr;
        int inc;
        long[] r_int_v = new long[128];
        long[] r_int_h = new long[128];
        long[] b_int_v = new long[64];
        long[] b_int_h = new long[64];
        if (rev == 0) {
            bits_ptr = (this.SYS_T * 2) + 40;
            inc = 0;
        } else {
            bits_ptr = (this.SYS_T * 2) + 40 + 12288;
            inc = -1024;
        }
        for (int i = 0; i < 64; i++) {
            r_int_v[i + 0] = Utils.load8(r, (i * 16) + 0 + 0);
            r_int_v[i + 64] = Utils.load8(r, (i * 16) + 0 + 8);
        }
        transpose_64x64(r_int_h, r_int_v, 0);
        transpose_64x64(r_int_h, r_int_v, 64);
        for (int iter = 0; iter <= 6; iter++) {
            for (int i2 = 0; i2 < 64; i2++) {
                b_int_v[i2] = Utils.load8(bits, bits_ptr);
                bits_ptr += 8;
            }
            bits_ptr += inc;
            transpose_64x64(b_int_h, b_int_v);
            layer_ex(r_int_h, b_int_h, iter);
        }
        transpose_64x64(r_int_v, r_int_h, 0);
        transpose_64x64(r_int_v, r_int_h, 64);
        for (int iter2 = 0; iter2 <= 5; iter2++) {
            for (int i3 = 0; i3 < 64; i3++) {
                b_int_v[i3] = Utils.load8(bits, bits_ptr);
                bits_ptr += 8;
            }
            bits_ptr += inc;
            layer_in(r_int_v, b_int_v, iter2);
        }
        for (int iter3 = 4; iter3 >= 0; iter3--) {
            for (int i4 = 0; i4 < 64; i4++) {
                b_int_v[i4] = Utils.load8(bits, bits_ptr);
                bits_ptr += 8;
            }
            bits_ptr += inc;
            layer_in(r_int_v, b_int_v, iter3);
        }
        transpose_64x64(r_int_h, r_int_v, 0);
        transpose_64x64(r_int_h, r_int_v, 64);
        for (int iter4 = 6; iter4 >= 0; iter4--) {
            for (int i5 = 0; i5 < 64; i5++) {
                b_int_v[i5] = Utils.load8(bits, bits_ptr);
                bits_ptr += 8;
            }
            bits_ptr += inc;
            transpose_64x64(b_int_h, b_int_v);
            layer_ex(r_int_h, b_int_h, iter4);
        }
        transpose_64x64(r_int_v, r_int_h, 0);
        transpose_64x64(r_int_v, r_int_h, 64);
        for (int i6 = 0; i6 < 64; i6++) {
            Utils.store8(r, (i6 * 16) + 0 + 0, r_int_v[i6 + 0]);
            Utils.store8(r, (i6 * 16) + 0 + 8, r_int_v[i6 + 64]);
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.cmce.BENES
    public void support_gen(short[] s, byte[] c) {
        byte[][] L = (byte[][]) Array.newInstance(Byte.TYPE, this.GFBITS, (1 << this.GFBITS) / 8);
        for (int i = 0; i < this.GFBITS; i++) {
            for (int j = 0; j < (1 << this.GFBITS) / 8; j++) {
                L[i][j] = 0;
            }
        }
        for (int i2 = 0; i2 < (1 << this.GFBITS); i2++) {
            short a = Utils.bitrev((short) i2, this.GFBITS);
            for (int j2 = 0; j2 < this.GFBITS; j2++) {
                byte[] bArr = L[j2];
                int i3 = i2 / 8;
                bArr[i3] = (byte) (bArr[i3] | (((a >> j2) & 1) << (i2 % 8)));
            }
        }
        for (int j3 = 0; j3 < this.GFBITS; j3++) {
            apply_benes(L[j3], c, 0);
        }
        for (int i4 = 0; i4 < this.SYS_N; i4++) {
            s[i4] = 0;
            for (int j4 = this.GFBITS - 1; j4 >= 0; j4--) {
                s[i4] = (short) (s[i4] << 1);
                s[i4] = (short) (s[i4] | ((L[j4][i4 / 8] >> (i4 % 8)) & 1));
            }
        }
    }
}
