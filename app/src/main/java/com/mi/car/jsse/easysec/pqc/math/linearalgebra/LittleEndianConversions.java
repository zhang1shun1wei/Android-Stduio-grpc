package com.mi.car.jsse.easysec.pqc.math.linearalgebra;

public final class LittleEndianConversions {
    private LittleEndianConversions() {
    }

    public static int OS2IP(byte[] input) {
        return (input[0] & 255) | ((input[1] & 255) << 8) | ((input[2] & 255) << 16) | ((input[3] & 255) << 24);
    }

    public static int OS2IP(byte[] input, int inOff) {
        int inOff2 = inOff + 1;
        int inOff3 = inOff2 + 1;
        return (input[inOff] & 255) | ((input[inOff2] & 255) << 8) | ((input[inOff3] & 255) << 16) | ((input[inOff3 + 1] & 255) << 24);
    }

    public static int OS2IP(byte[] input, int inOff, int inLen) {
        int result = 0;
        for (int i = inLen - 1; i >= 0; i--) {
            result |= (input[inOff + i] & 255) << (i * 8);
        }
        return result;
    }

    public static long OS2LIP(byte[] input, int inOff) {
        int inOff2 = inOff + 1;
        int inOff3 = inOff2 + 1;
        int inOff4 = inOff3 + 1;
        int inOff5 = inOff4 + 1;
        int inOff6 = inOff5 + 1;
        int inOff7 = inOff6 + 1;
        int inOff8 = inOff7 + 1;
        int i = inOff8 + 1;
        return ((long) (input[inOff] & 255)) | ((long) ((input[inOff2] & 255) << 8)) | ((long) ((input[inOff3] & 255) << 16)) | ((((long) input[inOff4]) & 255) << 24) | ((((long) input[inOff5]) & 255) << 32) | ((((long) input[inOff6]) & 255) << 40) | ((((long) input[inOff7]) & 255) << 48) | ((((long) input[inOff8]) & 255) << 56);
    }

    public static byte[] I2OSP(int x) {
        return new byte[]{(byte) x, (byte) (x >>> 8), (byte) (x >>> 16), (byte) (x >>> 24)};
    }

    public static void I2OSP(int value, byte[] output, int outOff) {
        int outOff2 = outOff + 1;
        output[outOff] = (byte) value;
        int outOff3 = outOff2 + 1;
        output[outOff2] = (byte) (value >>> 8);
        int outOff4 = outOff3 + 1;
        output[outOff3] = (byte) (value >>> 16);
        int i = outOff4 + 1;
        output[outOff4] = (byte) (value >>> 24);
    }

    public static void I2OSP(int value, byte[] output, int outOff, int outLen) {
        for (int i = outLen - 1; i >= 0; i--) {
            output[outOff + i] = (byte) (value >>> (i * 8));
        }
    }

    public static byte[] I2OSP(long input) {
        return new byte[]{(byte) ((int) input), (byte) ((int) (input >>> 8)), (byte) ((int) (input >>> 16)), (byte) ((int) (input >>> 24)), (byte) ((int) (input >>> 32)), (byte) ((int) (input >>> 40)), (byte) ((int) (input >>> 48)), (byte) ((int) (input >>> 56))};
    }

    public static void I2OSP(long input, byte[] output, int outOff) {
        int outOff2 = outOff + 1;
        output[outOff] = (byte) ((int) input);
        int outOff3 = outOff2 + 1;
        output[outOff2] = (byte) ((int) (input >>> 8));
        int outOff4 = outOff3 + 1;
        output[outOff3] = (byte) ((int) (input >>> 16));
        int outOff5 = outOff4 + 1;
        output[outOff4] = (byte) ((int) (input >>> 24));
        int outOff6 = outOff5 + 1;
        output[outOff5] = (byte) ((int) (input >>> 32));
        int outOff7 = outOff6 + 1;
        output[outOff6] = (byte) ((int) (input >>> 40));
        output[outOff7] = (byte) ((int) (input >>> 48));
        output[outOff7 + 1] = (byte) ((int) (input >>> 56));
    }

    public static byte[] toByteArray(int[] input, int outLen) {
        int intLen = input.length;
        byte[] result = new byte[outLen];
        int index = 0;
        int i = 0;
        while (i <= intLen - 2) {
            I2OSP(input[i], result, index);
            i++;
            index += 4;
        }
        I2OSP(input[intLen - 1], result, index, outLen - index);
        return result;
    }

    public static int[] toIntArray(byte[] input) {
        int intLen = (input.length + 3) / 4;
        int lastLen = input.length & 3;
        int[] result = new int[intLen];
        int index = 0;
        int i = 0;
        while (i <= intLen - 2) {
            result[i] = OS2IP(input, index);
            i++;
            index += 4;
        }
        if (lastLen != 0) {
            result[intLen - 1] = OS2IP(input, index, lastLen);
        } else {
            result[intLen - 1] = OS2IP(input, index);
        }
        return result;
    }
}
