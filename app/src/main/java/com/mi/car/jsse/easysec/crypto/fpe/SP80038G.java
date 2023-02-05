package com.mi.car.jsse.easysec.crypto.fpe;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.BigIntegers;
import com.mi.car.jsse.easysec.util.Pack;
import java.math.BigInteger;

class SP80038G {
    protected static final int BLOCK_SIZE = 16;
    static final String FF1_DISABLED = "com.mi.car.jsse.easysec.fpe.disable_ff1";
    static final String FPE_DISABLED = "com.mi.car.jsse.easysec.fpe.disable";
    protected static final double LOG2 = Math.log(2.0d);
    protected static final double TWO_TO_96 = Math.pow(2.0d, 96.0d);

    SP80038G() {
    }

    static byte[] decryptFF1(BlockCipher cipher, int radix, byte[] tweak, byte[] buf, int off, int len) {
        checkArgs(cipher, true, radix, buf, off, len);
        int u = len / 2;
        int v = len - u;
        return toByte(decFF1(cipher, radix, tweak, len, u, v, toShort(buf, off, u), toShort(buf, off + u, v)));
    }

    static short[] decryptFF1w(BlockCipher cipher, int radix, byte[] tweak, short[] buf, int off, int len) {
        checkArgs(cipher, true, radix, buf, off, len);
        int u = len / 2;
        int v = len - u;
        short[] A = new short[u];
        short[] B = new short[v];
        System.arraycopy(buf, off, A, 0, u);
        System.arraycopy(buf, off + u, B, 0, v);
        return decFF1(cipher, radix, tweak, len, u, v, A, B);
    }

    static short[] decFF1(BlockCipher cipher, int radix, byte[] T, int n, int u, int v, short[] A, short[] B) {
        int t = T.length;
        int b = (((int) Math.ceil((Math.log((double) radix) * ((double) v)) / LOG2)) + 7) / 8;
        int d = (((b + 3) / 4) * 4) + 4;
        byte[] P = calculateP_FF1(radix, (byte) u, n, t);
        BigInteger bigRadix = BigInteger.valueOf((long) radix);
        BigInteger[] modUV = calculateModUV(bigRadix, u, v);
        int m = u;
        for (int i = 9; i >= 0; i--) {
            BigInteger y = calculateY_FF1(cipher, bigRadix, T, b, d, i, P, A);
            m = n - m;
            B = A;
            A = B;
            str(bigRadix, num(bigRadix, B).subtract(y).mod(modUV[i & 1]), m, B, 0);
        }
        return Arrays.concatenate(A, B);
    }

    static byte[] decryptFF3(BlockCipher cipher, int radix, byte[] tweak64, byte[] buf, int off, int len) {
        checkArgs(cipher, false, radix, buf, off, len);
        if (tweak64.length == 8) {
            return implDecryptFF3(cipher, radix, tweak64, buf, off, len);
        }
        throw new IllegalArgumentException();
    }

    static byte[] decryptFF3_1(BlockCipher cipher, int radix, byte[] tweak56, byte[] buf, int off, int len) {
        checkArgs(cipher, false, radix, buf, off, len);
        if (tweak56.length == 7) {
            return implDecryptFF3(cipher, radix, calculateTweak64_FF3_1(tweak56), buf, off, len);
        }
        throw new IllegalArgumentException("tweak should be 56 bits");
    }

    static short[] decryptFF3_1w(BlockCipher cipher, int radix, byte[] tweak56, short[] buf, int off, int len) {
        checkArgs(cipher, false, radix, buf, off, len);
        if (tweak56.length == 7) {
            return implDecryptFF3w(cipher, radix, calculateTweak64_FF3_1(tweak56), buf, off, len);
        }
        throw new IllegalArgumentException("tweak should be 56 bits");
    }

    static byte[] encryptFF1(BlockCipher cipher, int radix, byte[] tweak, byte[] buf, int off, int len) {
        checkArgs(cipher, true, radix, buf, off, len);
        int u = len / 2;
        int v = len - u;
        return toByte(encFF1(cipher, radix, tweak, len, u, v, toShort(buf, off, u), toShort(buf, off + u, v)));
    }

    static short[] encryptFF1w(BlockCipher cipher, int radix, byte[] tweak, short[] buf, int off, int len) {
        checkArgs(cipher, true, radix, buf, off, len);
        int u = len / 2;
        int v = len - u;
        short[] A = new short[u];
        short[] B = new short[v];
        System.arraycopy(buf, off, A, 0, u);
        System.arraycopy(buf, off + u, B, 0, v);
        return encFF1(cipher, radix, tweak, len, u, v, A, B);
    }

    private static short[] encFF1(BlockCipher cipher, int radix, byte[] T, int n, int u, int v, short[] A, short[] B) {
        int t = T.length;
        int b = (((int) Math.ceil((Math.log((double) radix) * ((double) v)) / LOG2)) + 7) / 8;
        int d = (((b + 3) / 4) * 4) + 4;
        byte[] P = calculateP_FF1(radix, (byte) u, n, t);
        BigInteger bigRadix = BigInteger.valueOf((long) radix);
        BigInteger[] modUV = calculateModUV(bigRadix, u, v);
        int m = v;
        for (int i = 0; i < 10; i++) {
            BigInteger y = calculateY_FF1(cipher, bigRadix, T, b, d, i, P, B);
            m = n - m;
            A = B;
            B = A;
            str(bigRadix, num(bigRadix, A).add(y).mod(modUV[i & 1]), m, A, 0);
        }
        return Arrays.concatenate(A, B);
    }

    static byte[] encryptFF3(BlockCipher cipher, int radix, byte[] tweak64, byte[] buf, int off, int len) {
        checkArgs(cipher, false, radix, buf, off, len);
        if (tweak64.length == 8) {
            return implEncryptFF3(cipher, radix, tweak64, buf, off, len);
        }
        throw new IllegalArgumentException();
    }

    static short[] encryptFF3w(BlockCipher cipher, int radix, byte[] tweak64, short[] buf, int off, int len) {
        checkArgs(cipher, false, radix, buf, off, len);
        if (tweak64.length == 8) {
            return implEncryptFF3w(cipher, radix, tweak64, buf, off, len);
        }
        throw new IllegalArgumentException();
    }

    static short[] encryptFF3_1w(BlockCipher cipher, int radix, byte[] tweak56, short[] buf, int off, int len) {
        checkArgs(cipher, false, radix, buf, off, len);
        if (tweak56.length == 7) {
            return encryptFF3w(cipher, radix, calculateTweak64_FF3_1(tweak56), buf, off, len);
        }
        throw new IllegalArgumentException("tweak should be 56 bits");
    }

    static byte[] encryptFF3_1(BlockCipher cipher, int radix, byte[] tweak56, byte[] buf, int off, int len) {
        checkArgs(cipher, false, radix, buf, off, len);
        if (tweak56.length == 7) {
            return encryptFF3(cipher, radix, calculateTweak64_FF3_1(tweak56), buf, off, len);
        }
        throw new IllegalArgumentException("tweak should be 56 bits");
    }

    protected static BigInteger[] calculateModUV(BigInteger bigRadix, int u, int v) {
        BigInteger[] modUV = new BigInteger[2];
        modUV[0] = bigRadix.pow(u);
        modUV[1] = modUV[0];
        if (v != u) {
            modUV[1] = modUV[1].multiply(bigRadix);
        }
        return modUV;
    }

    protected static byte[] calculateP_FF1(int radix, byte uLow, int n, int t) {
        byte[] P = new byte[16];
        P[0] = 1;
        P[1] = 2;
        P[2] = 1;
        P[3] = 0;
        P[4] = (byte) (radix >> 8);
        P[5] = (byte) radix;
        P[6] = 10;
        P[7] = uLow;
        Pack.intToBigEndian(n, P, 8);
        Pack.intToBigEndian(t, P, 12);
        return P;
    }

    protected static byte[] calculateTweak64_FF3_1(byte[] tweak56) {
        return new byte[]{tweak56[0], tweak56[1], tweak56[2], (byte) (tweak56[3] & 240), tweak56[4], tweak56[5], tweak56[6], (byte) (tweak56[3] << 4)};
    }

    protected static BigInteger calculateY_FF1(BlockCipher cipher, BigInteger bigRadix, byte[] T, int b, int d, int round, byte[] P, short[] AB) {
        int t = T.length;
        byte[] bytesAB = BigIntegers.asUnsignedByteArray(num(bigRadix, AB));
        int zeroes = (-(t + b + 1)) & 15;
        byte[] Q = new byte[(t + zeroes + 1 + b)];
        System.arraycopy(T, 0, Q, 0, t);
        Q[t + zeroes] = (byte) round;
        System.arraycopy(bytesAB, 0, Q, Q.length - bytesAB.length, bytesAB.length);
        byte[] R = prf(cipher, Arrays.concatenate(P, Q));
        byte[] sBlocks = R;
        if (d > 16) {
            int sBlocksLen = ((d + 16) - 1) / 16;
            sBlocks = new byte[(sBlocksLen * 16)];
            System.arraycopy(R, 0, sBlocks, 0, 16);
            byte[] uint32 = new byte[4];
            for (int j = 1; j < sBlocksLen; j++) {
                int sOff = j * 16;
                System.arraycopy(R, 0, sBlocks, sOff, 16);
                Pack.intToBigEndian(j, uint32, 0);
                xor(uint32, 0, sBlocks, (sOff + 16) - 4, 4);
                cipher.processBlock(sBlocks, sOff, sBlocks, sOff);
            }
        }
        return num(sBlocks, 0, d);
    }

    protected static BigInteger calculateY_FF3(BlockCipher cipher, BigInteger bigRadix, byte[] T, int wOff, int round, short[] AB) {
        byte[] P = new byte[16];
        Pack.intToBigEndian(round, P, 0);
        xor(T, wOff, P, 0, 4);
        byte[] bytesAB = BigIntegers.asUnsignedByteArray(num(bigRadix, AB));
        if (P.length - bytesAB.length < 4) {
            throw new IllegalStateException("input out of range");
        }
        System.arraycopy(bytesAB, 0, P, P.length - bytesAB.length, bytesAB.length);
        rev(P);
        cipher.processBlock(P, 0, P, 0);
        rev(P);
        return num(P, 0, P.length);
    }

    protected static void checkArgs(BlockCipher cipher, boolean isFF1, int radix, short[] buf, int off, int len) {
        checkCipher(cipher);
        if (radix < 2 || radix > 65536) {
            throw new IllegalArgumentException();
        }
        checkData(isFF1, radix, buf, off, len);
    }

    protected static void checkArgs(BlockCipher cipher, boolean isFF1, int radix, byte[] buf, int off, int len) {
        checkCipher(cipher);
        if (radix < 2 || radix > 256) {
            throw new IllegalArgumentException();
        }
        checkData(isFF1, radix, buf, off, len);
    }

    protected static void checkCipher(BlockCipher cipher) {
        if (16 != cipher.getBlockSize()) {
            throw new IllegalArgumentException();
        }
    }

    protected static void checkData(boolean isFF1, int radix, short[] buf, int off, int len) {
        checkLength(isFF1, radix, len);
        for (int i = 0; i < len; i++) {
            if ((buf[off + i] & 65535) >= radix) {
                throw new IllegalArgumentException("input data outside of radix");
            }
        }
    }

    protected static void checkData(boolean isFF1, int radix, byte[] buf, int off, int len) {
        checkLength(isFF1, radix, len);
        for (int i = 0; i < len; i++) {
            if ((buf[off + i] & 255) >= radix) {
                throw new IllegalArgumentException("input data outside of radix");
            }
        }
    }

    private static void checkLength(boolean isFF1, int radix, int len) {
        int maxLen;
        if (len < 2 || Math.pow((double) radix, (double) len) < 1000000.0d) {
            throw new IllegalArgumentException("input too short");
        } else if (!isFF1 && len > (maxLen = ((int) Math.floor(Math.log(TWO_TO_96) / Math.log((double) radix))) * 2)) {
            throw new IllegalArgumentException("maximum input length is " + maxLen);
        }
    }

    protected static byte[] implDecryptFF3(BlockCipher cipher, int radix, byte[] tweak64, byte[] buf, int off, int len) {
        int v = len / 2;
        int u = len - v;
        return toByte(decFF3_1(cipher, radix, tweak64, len, v, u, toShort(buf, off, u), toShort(buf, off + u, v)));
    }

    protected static short[] implDecryptFF3w(BlockCipher cipher, int radix, byte[] tweak64, short[] buf, int off, int len) {
        int v = len / 2;
        int u = len - v;
        short[] A = new short[u];
        short[] B = new short[v];
        System.arraycopy(buf, off, A, 0, u);
        System.arraycopy(buf, off + u, B, 0, v);
        return decFF3_1(cipher, radix, tweak64, len, v, u, A, B);
    }

    private static short[] decFF3_1(BlockCipher cipher, int radix, byte[] T, int n, int v, int u, short[] A, short[] B) {
        BigInteger bigRadix = BigInteger.valueOf((long) radix);
        BigInteger[] modVU = calculateModUV(bigRadix, v, u);
        int m = u;
        rev(A);
        rev(B);
        for (int i = 7; i >= 0; i--) {
            m = n - m;
            BigInteger modulus = modVU[1 - (i & 1)];
            BigInteger y = calculateY_FF3(cipher, bigRadix, T, 4 - ((i & 1) * 4), i, A);
            B = A;
            A = B;
            str(bigRadix, num(bigRadix, B).subtract(y).mod(modulus), m, B, 0);
        }
        rev(A);
        rev(B);
        return Arrays.concatenate(A, B);
    }

    protected static byte[] implEncryptFF3(BlockCipher cipher, int radix, byte[] tweak64, byte[] buf, int off, int len) {
        int v = len / 2;
        int u = len - v;
        return toByte(encFF3_1(cipher, radix, tweak64, len, v, u, toShort(buf, off, u), toShort(buf, off + u, v)));
    }

    protected static short[] implEncryptFF3w(BlockCipher cipher, int radix, byte[] tweak64, short[] buf, int off, int len) {
        int v = len / 2;
        int u = len - v;
        short[] A = new short[u];
        short[] B = new short[v];
        System.arraycopy(buf, off, A, 0, u);
        System.arraycopy(buf, off + u, B, 0, v);
        return encFF3_1(cipher, radix, tweak64, len, v, u, A, B);
    }

    private static short[] encFF3_1(BlockCipher cipher, int radix, byte[] t, int n, int v, int u, short[] a, short[] b) {
        BigInteger bigRadix = BigInteger.valueOf((long) radix);
        BigInteger[] modVU = calculateModUV(bigRadix, v, u);
        int m = v;
        rev(a);
        rev(b);
        for (int i = 0; i < 8; i++) {
            m = n - m;
            BigInteger modulus = modVU[1 - (i & 1)];
            BigInteger y = calculateY_FF3(cipher, bigRadix, t, 4 - ((i & 1) * 4), i, b);
            a = b;
            b = a;
            str(bigRadix, num(bigRadix, a).add(y).mod(modulus), m, a, 0);
        }
        rev(a);
        rev(b);
        return Arrays.concatenate(a, b);
    }

    protected static BigInteger num(byte[] buf, int off, int len) {
        return new BigInteger(1, Arrays.copyOfRange(buf, off, off + len));
    }

    protected static BigInteger num(BigInteger R, short[] x) {
        BigInteger result = BigIntegers.ZERO;
        for (short s : x) {
            result = result.multiply(R).add(BigInteger.valueOf((long) (s & 65535)));
        }
        return result;
    }

    protected static byte[] prf(BlockCipher c, byte[] x) {
        if (x.length % 16 != 0) {
            throw new IllegalArgumentException();
        }
        int m = x.length / 16;
        byte[] y = new byte[16];
        for (int i = 0; i < m; i++) {
            xor(x, i * 16, y, 0, 16);
            c.processBlock(y, 0, y, 0);
        }
        return y;
    }

    protected static void rev(byte[] x) {
        int half = x.length / 2;
        int end = x.length - 1;
        for (int i = 0; i < half; i++) {
            byte tmp = x[i];
            x[i] = x[end - i];
            x[end - i] = tmp;
        }
    }

    protected static void rev(short[] x) {
        int half = x.length / 2;
        int end = x.length - 1;
        for (int i = 0; i < half; i++) {
            short tmp = x[i];
            x[i] = x[end - i];
            x[end - i] = tmp;
        }
    }

    protected static void str(BigInteger R, BigInteger x, int m, short[] output, int off) {
        if (x.signum() < 0) {
            throw new IllegalArgumentException();
        }
        for (int i = 1; i <= m; i++) {
            BigInteger[] qr = x.divideAndRemainder(R);
            output[(off + m) - i] = (short) qr[1].intValue();
            x = qr[0];
        }
        if (x.signum() != 0) {
            throw new IllegalArgumentException();
        }
    }

    protected static void xor(byte[] x, int xOff, byte[] y, int yOff, int len) {
        for (int i = 0; i < len; i++) {
            int i2 = yOff + i;
            y[i2] = (byte) (y[i2] ^ x[xOff + i]);
        }
    }

    private static byte[] toByte(short[] buf) {
        byte[] s = new byte[buf.length];
        for (int i = 0; i != s.length; i++) {
            s[i] = (byte) buf[i];
        }
        return s;
    }

    private static short[] toShort(byte[] buf, int off, int len) {
        short[] s = new short[len];
        for (int i = 0; i != s.length; i++) {
            s[i] = (short) (buf[off + i] & 255);
        }
        return s;
    }
}
