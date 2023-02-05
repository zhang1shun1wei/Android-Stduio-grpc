package com.mi.car.jsse.easysec.pqc.crypto.cmce;

class GF13 extends GF {
    public GF13(int gfbits) {
        super(gfbits);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.crypto.cmce.GF
    public short gf_mul(short in0, short in1) {
        long t0 = (long) in0;
        long t1 = (long) in1;
        long tmp = t0 * (1 & t1);
        for (int i = 1; i < this.GFBITS; i++) {
            tmp ^= (((long) (1 << i)) & t1) * t0;
        }
        long t = tmp & 33488896;
        long tmp2 = tmp ^ ((((t >> 9) ^ (t >> 10)) ^ (t >> 12)) ^ (t >> 13));
        long t2 = tmp2 & 57344;
        return (short) ((int) (((long) this.GFMASK) & (tmp2 ^ ((((t2 >> 9) ^ (t2 >> 10)) ^ (t2 >> 12)) ^ (t2 >> 13)))));
    }

    /* access modifiers changed from: protected */
    public short gf_sq2(short in) {
        long[] B = {1229782938247303441L, 217020518514230019L, 4222189076152335L, 1095216660735L};
        long[] M = {561850441793536L, 1097364144128L, 2143289344, 4186112};
        long x = (long) in;
        long x2 = ((x << 24) | x) & B[3];
        long x3 = ((x2 << 12) | x2) & B[2];
        long x4 = ((x3 << 6) | x3) & B[1];
        long x5 = ((x4 << 3) | x4) & B[0];
        for (int i = 0; i < 4; i++) {
            long t = x5 & M[i];
            x5 ^= (((t >> 9) ^ (t >> 10)) ^ (t >> 12)) ^ (t >> 13);
        }
        return (short) ((int) (((long) this.GFMASK) & x5));
    }

    private short gf_sqmul(short in, short m) {
        long[] M = {137170518016L, 267911168, 516096};
        long t0 = (long) in;
        long t1 = (long) m;
        long x = (t1 << 6) * (64 & t0);
        long t02 = t0 ^ (t0 << 7);
        long x2 = (((((x ^ ((16385 & t02) * t1)) ^ (((32770 & t02) * t1) << 1)) ^ (((65540 & t02) * t1) << 2)) ^ (((131080 & t02) * t1) << 3)) ^ (((262160 & t02) * t1) << 4)) ^ (((524320 & t02) * t1) << 5);
        for (int i = 0; i < 3; i++) {
            long t = x2 & M[i];
            x2 ^= (((t >> 9) ^ (t >> 10)) ^ (t >> 12)) ^ (t >> 13);
        }
        return (short) ((int) (((long) this.GFMASK) & x2));
    }

    private short gf_sq2mul(short in, short m) {
        long[] M = {2301339409586323456L, 4494803534348288L, 8778913153024L, 17146314752L, 33423360, 122880};
        long t0 = (long) in;
        long t1 = (long) m;
        long x = (t1 << 18) * (64 & t0);
        long t02 = t0 ^ (t0 << 21);
        long x2 = (((((x ^ ((268435457 & t02) * t1)) ^ (((536870914 & t02) * t1) << 3)) ^ (((1073741828 & t02) * t1) << 6)) ^ (((2147483656L & t02) * t1) << 9)) ^ (((4294967312L & t02) * t1) << 12)) ^ (((8589934624L & t02) * t1) << 15);
        for (int i = 0; i < 6; i++) {
            long t = x2 & M[i];
            x2 ^= (((t >> 9) ^ (t >> 10)) ^ (t >> 12)) ^ (t >> 13);
        }
        return (short) ((int) (((long) this.GFMASK) & x2));
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.crypto.cmce.GF
    public short gf_frac(short den, short num) {
        short tmp_11 = gf_sqmul(den, den);
        short tmp_1111 = gf_sq2mul(tmp_11, tmp_11);
        return gf_sqmul(gf_sq2mul(gf_sq2(gf_sq2mul(gf_sq2(tmp_1111), tmp_1111)), tmp_1111), num);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.crypto.cmce.GF
    public short gf_inv(short den) {
        return gf_frac(den, (short) 1);
    }
}
