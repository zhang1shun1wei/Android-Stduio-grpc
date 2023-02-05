package com.mi.car.jsse.easysec.pqc.crypto.cmce;

import java.lang.reflect.Array;

class BENES12 extends BENES {
    public BENES12(int n, int t, int m) {
        super(n, t, m);
    }

    static void layerBenes(long[] data, long[] bits, int lgs) {
        int bit_ptr = 0;
        int s = 1 << lgs;
        int i = 0;
        while (i < 64) {
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

    private void apply_benes(byte[] r, byte[] bits, int rev) {
        int inc;
        int cond_ptr;
        long[] bs = new long[64];
        long[] cond = new long[64];
        for (int i = 0; i < 64; i++) {
            bs[i] = Utils.load8(r, i * 8);
        }
        if (rev == 0) {
            inc = 256;
            cond_ptr = (this.SYS_T * 2) + 40;
        } else {
            inc = -256;
            cond_ptr = (this.SYS_T * 2) + 40 + (((this.GFBITS * 2) - 2) * 256);
        }
        transpose_64x64(bs, bs);
        for (int low = 0; low <= 5; low++) {
            for (int i2 = 0; i2 < 64; i2++) {
                cond[i2] = (long) Utils.load4(bits, (i2 * 4) + cond_ptr);
            }
            transpose_64x64(cond, cond);
            layerBenes(bs, cond, low);
            cond_ptr += inc;
        }
        transpose_64x64(bs, bs);
        for (int low2 = 0; low2 <= 5; low2++) {
            for (int i3 = 0; i3 < 32; i3++) {
                cond[i3] = Utils.load8(bits, (i3 * 8) + cond_ptr);
            }
            layerBenes(bs, cond, low2);
            cond_ptr += inc;
        }
        for (int low3 = 4; low3 >= 0; low3--) {
            for (int i4 = 0; i4 < 32; i4++) {
                cond[i4] = Utils.load8(bits, (i4 * 8) + cond_ptr);
            }
            layerBenes(bs, cond, low3);
            cond_ptr += inc;
        }
        transpose_64x64(bs, bs);
        for (int low4 = 5; low4 >= 0; low4--) {
            for (int i5 = 0; i5 < 64; i5++) {
                cond[i5] = (long) Utils.load4(bits, (i5 * 4) + cond_ptr);
            }
            transpose_64x64(cond, cond);
            layerBenes(bs, cond, low4);
            cond_ptr += inc;
        }
        transpose_64x64(bs, bs);
        for (int i6 = 0; i6 < 64; i6++) {
            Utils.store8(r, i6 * 8, bs[i6]);
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
