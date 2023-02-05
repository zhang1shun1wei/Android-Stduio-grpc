package com.mi.car.jsse.easysec.pqc.crypto.cmce;

import com.mi.car.jsse.easysec.util.Pack;

class Utils {
    Utils() {
    }

    static void store_gf(byte[] dest, int offset, short a) {
        dest[offset + 0] = (byte) (a & 255);
        dest[offset + 1] = (byte) (a >> 8);
    }

    static short load_gf(byte[] src, int offset, int gfmask) {
        return (short) (Pack.littleEndianToShort(src, offset) & gfmask);
    }

    static int load4(byte[] in, int offset) {
        return Pack.littleEndianToInt(in, offset);
    }

    static void store8(byte[] out, int offset, long in) {
        out[offset + 0] = (byte) ((int) ((in >> 0) & 255));
        out[offset + 1] = (byte) ((int) ((in >> 8) & 255));
        out[offset + 2] = (byte) ((int) ((in >> 16) & 255));
        out[offset + 3] = (byte) ((int) ((in >> 24) & 255));
        out[offset + 4] = (byte) ((int) ((in >> 32) & 255));
        out[offset + 5] = (byte) ((int) ((in >> 40) & 255));
        out[offset + 6] = (byte) ((int) ((in >> 48) & 255));
        out[offset + 7] = (byte) ((int) ((in >> 56) & 255));
    }

    static long load8(byte[] in, int offset) {
        return Pack.littleEndianToLong(in, offset);
    }

    static short bitrev(short a, int GFBITS) {
        short a2 = (short) (((a & 255) << 8) | ((65280 & a) >> 8));
        short a3 = (short) (((a2 & 3855) << 4) | ((61680 & a2) >> 4));
        short a4 = (short) (((a3 & 13107) << 2) | ((52428 & a3) >> 2));
        short a5 = (short) (((a4 & 21845) << 1) | ((43690 & a4) >> 1));
        if (GFBITS == 12) {
            return (short) (a5 >> 4);
        }
        return (short) (a5 >> 3);
    }
}
