package com.mi.car.jsse.easysec.pqc.crypto.sphincs;

import com.mi.car.jsse.easysec.util.Pack;

class Permute {
    private static final int CHACHA_ROUNDS = 12;

    Permute() {
    }

    protected static int rotl(int x, int y) {
        return (x << y) | (x >>> (-y));
    }

    public static void permute(int rounds, int[] x) {
        if (x.length != 16) {
            throw new IllegalArgumentException();
        } else if (rounds % 2 != 0) {
            throw new IllegalArgumentException("Number of rounds must be even");
        } else {
            int x00 = x[0];
            int x01 = x[1];
            int x02 = x[2];
            int x03 = x[3];
            int x04 = x[4];
            int x05 = x[5];
            int x06 = x[6];
            int x07 = x[7];
            int x08 = x[8];
            int x09 = x[9];
            int x10 = x[10];
            int x11 = x[11];
            int x12 = x[12];
            int x13 = x[13];
            int x14 = x[14];
            int x15 = x[15];
            for (int i = rounds; i > 0; i -= 2) {
                int x002 = x00 + x04;
                int x122 = rotl(x12 ^ x002, 16);
                int x082 = x08 + x122;
                int x042 = rotl(x04 ^ x082, 12);
                int x003 = x002 + x042;
                int x123 = rotl(x122 ^ x003, 8);
                int x083 = x082 + x123;
                int x043 = rotl(x042 ^ x083, 7);
                int x012 = x01 + x05;
                int x132 = rotl(x13 ^ x012, 16);
                int x092 = x09 + x132;
                int x052 = rotl(x05 ^ x092, 12);
                int x013 = x012 + x052;
                int x133 = rotl(x132 ^ x013, 8);
                int x093 = x092 + x133;
                int x053 = rotl(x052 ^ x093, 7);
                int x022 = x02 + x06;
                int x142 = rotl(x14 ^ x022, 16);
                int x102 = x10 + x142;
                int x062 = rotl(x06 ^ x102, 12);
                int x023 = x022 + x062;
                int x143 = rotl(x142 ^ x023, 8);
                int x103 = x102 + x143;
                int x063 = rotl(x062 ^ x103, 7);
                int x032 = x03 + x07;
                int x152 = rotl(x15 ^ x032, 16);
                int x112 = x11 + x152;
                int x072 = rotl(x07 ^ x112, 12);
                int x033 = x032 + x072;
                int x153 = rotl(x152 ^ x033, 8);
                int x113 = x112 + x153;
                int x073 = rotl(x072 ^ x113, 7);
                int x004 = x003 + x053;
                int x154 = rotl(x153 ^ x004, 16);
                int x104 = x103 + x154;
                int x054 = rotl(x053 ^ x104, 12);
                x00 = x004 + x054;
                x15 = rotl(x154 ^ x00, 8);
                x10 = x104 + x15;
                x05 = rotl(x054 ^ x10, 7);
                int x014 = x013 + x063;
                int x124 = rotl(x123 ^ x014, 16);
                int x114 = x113 + x124;
                int x064 = rotl(x063 ^ x114, 12);
                x01 = x014 + x064;
                x12 = rotl(x124 ^ x01, 8);
                x11 = x114 + x12;
                x06 = rotl(x064 ^ x11, 7);
                int x024 = x023 + x073;
                int x134 = rotl(x133 ^ x024, 16);
                int x084 = x083 + x134;
                int x074 = rotl(x073 ^ x084, 12);
                x02 = x024 + x074;
                x13 = rotl(x134 ^ x02, 8);
                x08 = x084 + x13;
                x07 = rotl(x074 ^ x08, 7);
                int x034 = x033 + x043;
                int x144 = rotl(x143 ^ x034, 16);
                int x094 = x093 + x144;
                int x044 = rotl(x043 ^ x094, 12);
                x03 = x034 + x044;
                x14 = rotl(x144 ^ x03, 8);
                x09 = x094 + x14;
                x04 = rotl(x044 ^ x09, 7);
            }
            x[0] = x00;
            x[1] = x01;
            x[2] = x02;
            x[3] = x03;
            x[4] = x04;
            x[5] = x05;
            x[6] = x06;
            x[7] = x07;
            x[8] = x08;
            x[9] = x09;
            x[10] = x10;
            x[11] = x11;
            x[12] = x12;
            x[13] = x13;
            x[14] = x14;
            x[15] = x15;
        }
    }

    /* access modifiers changed from: package-private */
    public void chacha_permute(byte[] out, byte[] in) {
        int[] x = new int[16];
        for (int i = 0; i < 16; i++) {
            x[i] = Pack.littleEndianToInt(in, i * 4);
        }
        permute(12, x);
        for (int i2 = 0; i2 < 16; i2++) {
            Pack.intToLittleEndian(x[i2], out, i2 * 4);
        }
    }
}
