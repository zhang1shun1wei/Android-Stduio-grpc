package com.mi.car.jsse.easysec.pqc.crypto.cmce;

class GF12 extends GF {
    public GF12(int gfbits) {
        super(gfbits);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.crypto.cmce.GF
    public short gf_mul(short left, short right) {
        int temp = left * (right & 1);
        for (int i = 1; i < this.GFBITS; i++) {
            temp ^= ((1 << i) & right) * left;
        }
        int t = temp & 8372224;
        int temp2 = (temp ^ (t >> 9)) ^ (t >> 12);
        int t2 = temp2 & 12288;
        return (short) (((1 << this.GFBITS) - 1) & ((temp2 ^ (t2 >> 9)) ^ (t2 >> 12)));
    }

    /* access modifiers changed from: protected */
    public short gf_sq(short input) {
        int[] B = {1431655765, 858993459, 252645135, 16711935};
        int x = ((input << 8) | input) & B[3];
        int x2 = ((x << 4) | x) & B[2];
        int x3 = ((x2 << 2) | x2) & B[1];
        int x4 = ((x3 << 1) | x3) & B[0];
        int t = x4 & 8372224;
        int x5 = (x4 ^ (t >> 9)) ^ (t >> 12);
        int t2 = x5 & 12288;
        return (short) (((1 << this.GFBITS) - 1) & ((x5 ^ (t2 >> 9)) ^ (t2 >> 12)));
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.crypto.cmce.GF
    public short gf_inv(short input) {
        short tmp_11 = gf_mul(gf_sq(input), input);
        short tmp_1111 = gf_mul(gf_sq(gf_sq(tmp_11)), tmp_11);
        return gf_sq(gf_mul(gf_sq(gf_mul(gf_sq(gf_sq(gf_mul(gf_sq(gf_sq(gf_sq(gf_sq(tmp_1111)))), tmp_1111))), tmp_11)), input));
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.crypto.cmce.GF
    public short gf_frac(short den, short num) {
        return gf_mul(gf_inv(den), num);
    }
}
