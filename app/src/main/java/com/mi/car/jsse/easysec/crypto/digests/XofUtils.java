package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.util.Arrays;

public class XofUtils {
    public static byte[] leftEncode(long strLen) {
        byte n = 1;
        long v = strLen;
        while (true) {
            v >>= 8;
            if (v == 0) {
                break;
            }
            n = (byte) (n + 1);
        }
        byte[] b = new byte[(n + 1)];
        b[0] = n;
        for (int i = 1; i <= n; i++) {
            b[i] = (byte) ((int) (strLen >> ((n - i) * 8)));
        }
        return b;
    }

    public static byte[] rightEncode(long strLen) {
        byte n = 1;
        long v = strLen;
        while (true) {
            v >>= 8;
            if (v == 0) {
                break;
            }
            n = (byte) (n + 1);
        }
        byte[] b = new byte[(n + 1)];
        b[n] = n;
        for (int i = 0; i < n; i++) {
            b[i] = (byte) ((int) (strLen >> (((n - i) - 1) * 8)));
        }
        return b;
    }

    static byte[] encode(byte X) {
        return Arrays.concatenate(leftEncode(8), new byte[]{X});
    }

    static byte[] encode(byte[] in, int inOff, int len) {
        if (in.length == len) {
            return Arrays.concatenate(leftEncode((long) (len * 8)), in);
        }
        return Arrays.concatenate(leftEncode((long) (len * 8)), Arrays.copyOfRange(in, inOff, inOff + len));
    }
}
