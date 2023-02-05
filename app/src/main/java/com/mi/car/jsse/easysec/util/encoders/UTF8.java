package com.mi.car.jsse.easysec.util.encoders;

public class UTF8 {
    private static final byte C_CR1 = 1;
    private static final byte C_CR2 = 2;
    private static final byte C_CR3 = 3;
    private static final byte C_ILL = 0;
    private static final byte C_L2A = 4;
    private static final byte C_L3A = 5;
    private static final byte C_L3B = 6;
    private static final byte C_L3C = 7;
    private static final byte C_L4A = 8;
    private static final byte C_L4B = 9;
    private static final byte C_L4C = 10;
    private static final byte S_CS1 = 0;
    private static final byte S_CS2 = 16;
    private static final byte S_CS3 = 32;
    private static final byte S_END = -1;
    private static final byte S_ERR = -2;
    private static final byte S_P3A = 48;
    private static final byte S_P3B = 64;
    private static final byte S_P4A = 80;
    private static final byte S_P4B = 96;
    private static final short[] firstUnitTable = new short[128];
    private static final byte[] transitionTable = new byte[112];

    static {
        byte[] categories = new byte[128];
        fill(categories, 0, 15, C_CR1);
        fill(categories, 16, 31, C_CR2);
        fill(categories, 32, 63, C_CR3);
        fill(categories, 64, 65, (byte) 0);
        fill(categories, 66, 95, (byte) 4);
        fill(categories, 96, 96, C_L3A);
        fill(categories, 97, 108, C_L3B);
        fill(categories, 109, 109, C_L3C);
        fill(categories, 110, 111, C_L3B);
        fill(categories, 112, 112, C_L4A);
        fill(categories, 113, 115, C_L4B);
        fill(categories, 116, 116, C_L4C);
        fill(categories, 117, 127, (byte) 0);
        fill(transitionTable, 0, transitionTable.length - 1, S_ERR);
        fill(transitionTable, 8, 11, S_END);
        fill(transitionTable, 24, 27, (byte) 0);
        fill(transitionTable, 40, 43, (byte) 16);
        fill(transitionTable, 58, 59, (byte) 0);
        fill(transitionTable, 72, 73, (byte) 0);
        fill(transitionTable, 89, 91, (byte) 16);
        fill(transitionTable, 104, 104, (byte) 16);
        byte[] firstUnitMasks = {0, 0, 0, 0, 31, 15, 15, 15, C_L3C, C_L3C, C_L3C};
        byte[] firstUnitTransitions = {S_ERR, S_ERR, S_ERR, S_ERR, 0, S_P3A, 16, S_P3B, S_P4A, S_CS3, S_P4B};
        for (int i = 0; i < 128; i++) {
            byte category = categories[i];
            int codePoint = i & firstUnitMasks[category];
            firstUnitTable[i] = (short) ((codePoint << 8) | firstUnitTransitions[category]);
        }
    }

    private static void fill(byte[] table, int first, int last, byte b) {
        for (int i = first; i <= last; i++) {
            table[i] = b;
        }
    }

    public static int transcodeToUTF16(byte[] utf8, char[] utf16) {
        return transcodeToUTF16(utf8, 0, utf8.length, utf16);
    }

    public static int transcodeToUTF16(byte[] utf8, int utf8Off, int utf8Length, char[] utf16) {
        int j;
        int maxI = utf8Off + utf8Length;
        int j2 = 0;
        int i = utf8Off;
        while (i < maxI) {
            int i2 = i + 1;
            byte codeUnit = utf8[i];
            if (codeUnit < 0) {
                short first = firstUnitTable[codeUnit & Byte.MAX_VALUE];
                int codePoint = first >>> 8;
                byte state = (byte) first;
                i = i2;
                while (state >= 0) {
                    if (i >= utf8.length) {
                        return -1;
                    }
                    byte codeUnit2 = utf8[i];
                    codePoint = (codePoint << 6) | (codeUnit2 & 63);
                    state = transitionTable[((codeUnit2 & S_END) >>> 4) + state];
                    i++;
                }
                if (state == -2) {
                    return -1;
                }
                if (codePoint <= 65535) {
                    if (j2 >= utf16.length) {
                        return -1;
                    }
                    j = j2 + 1;
                    utf16[j2] = (char) codePoint;
                } else if (j2 >= utf16.length - 1) {
                    return -1;
                } else {
                    int j3 = j2 + 1;
                    utf16[j2] = (char) (55232 + (codePoint >>> 10));
                    utf16[j3] = (char) (56320 | (codePoint & 1023));
                    j = j3 + 1;
                }
                j2 = j;
            } else if (j2 >= utf16.length) {
                return -1;
            } else {
                utf16[j2] = (char) codeUnit;
                j2++;
                i = i2;
            }
        }
        return j2;
    }
}
