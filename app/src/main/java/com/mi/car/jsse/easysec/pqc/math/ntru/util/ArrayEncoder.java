package com.mi.car.jsse.easysec.pqc.math.ntru.util;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

public class ArrayEncoder {
    private static final int[] BIT1_TABLE = {1, 1, 1, 0, 0, 0, 1, 0, 1};
    private static final int[] BIT2_TABLE = {1, 1, 1, 1, 0, 0, 0, 1, 0};
    private static final int[] BIT3_TABLE = {1, 0, 1, 0, 0, 1, 1, 1, 0};
    private static final int[] COEFF1_TABLE = {0, 0, 0, 1, 1, 1, -1, -1};
    private static final int[] COEFF2_TABLE = {0, 1, -1, 0, 1, -1, 0, 1};

    public static byte[] encodeModQ(int[] a, int q) {
        int bitsPerCoeff = 31 - Integer.numberOfLeadingZeros(q);
        byte[] data = new byte[(((a.length * bitsPerCoeff) + 7) / 8)];
        int bitIndex = 0;
        int byteIndex = 0;
        for (int i = 0; i < a.length; i++) {
            for (int j = 0; j < bitsPerCoeff; j++) {
                data[byteIndex] = (byte) (data[byteIndex] | (((a[i] >> j) & 1) << bitIndex));
                if (bitIndex == 7) {
                    bitIndex = 0;
                    byteIndex++;
                } else {
                    bitIndex++;
                }
            }
        }
        return data;
    }

    public static int[] decodeModQ(byte[] data, int N, int q) {
        int[] coeffs = new int[N];
        int bitsPerCoeff = 31 - Integer.numberOfLeadingZeros(q);
        int numBits = N * bitsPerCoeff;
        int coeffIndex = 0;
        for (int bitIndex = 0; bitIndex < numBits; bitIndex++) {
            if (bitIndex > 0 && bitIndex % bitsPerCoeff == 0) {
                coeffIndex++;
            }
            coeffs[coeffIndex] = coeffs[coeffIndex] + (getBit(data, bitIndex) << (bitIndex % bitsPerCoeff));
        }
        return coeffs;
    }

    public static int[] decodeModQ(InputStream is, int N, int q) throws IOException {
        return decodeModQ(Util.readFullLength(is, ((N * (31 - Integer.numberOfLeadingZeros(q))) + 7) / 8), N, q);
    }

    public static int[] decodeMod3Sves(byte[] data, int N) {
        int[] coeffs = new int[N];
        int coeffIndex = 0;
        int bitIndex = 0;
        while (true) {
            if (bitIndex >= data.length * 8) {
                break;
            }
            int bitIndex2 = bitIndex + 1;
            int bit1 = getBit(data, bitIndex);
            int bitIndex3 = bitIndex2 + 1;
            int bit2 = getBit(data, bitIndex2);
            int bitIndex4 = bitIndex3 + 1;
            int coeffTableIndex = (bit1 * 4) + (bit2 * 2) + getBit(data, bitIndex3);
            int coeffIndex2 = coeffIndex + 1;
            coeffs[coeffIndex] = COEFF1_TABLE[coeffTableIndex];
            coeffIndex = coeffIndex2 + 1;
            coeffs[coeffIndex2] = COEFF2_TABLE[coeffTableIndex];
            if (coeffIndex > N - 2) {
                break;
            }
            bitIndex = bitIndex4;
        }
        return coeffs;
    }

    public static byte[] encodeMod3Sves(int[] arr) {
        byte[] data = new byte[(((((arr.length * 3) + 1) / 2) + 7) / 8)];
        int bitIndex = 0;
        int byteIndex = 0;
        int i = 0;
        while (i < (arr.length / 2) * 2) {
            int i2 = i + 1;
            int coeff1 = arr[i] + 1;
            i = i2 + 1;
            int coeff2 = arr[i2] + 1;
            if (coeff1 == 0 && coeff2 == 0) {
                throw new IllegalStateException("Illegal encoding!");
            }
            int bitTableIndex = (coeff1 * 3) + coeff2;
            int[] bits = {BIT1_TABLE[bitTableIndex], BIT2_TABLE[bitTableIndex], BIT3_TABLE[bitTableIndex]};
            for (int j = 0; j < 3; j++) {
                data[byteIndex] = (byte) (data[byteIndex] | (bits[j] << bitIndex));
                if (bitIndex == 7) {
                    bitIndex = 0;
                    byteIndex++;
                } else {
                    bitIndex++;
                }
            }
        }
        return data;
    }

    public static byte[] encodeMod3Tight(int[] intArray) {
        BigInteger sum = BigInteger.ZERO;
        for (int i = intArray.length - 1; i >= 0; i--) {
            sum = sum.multiply(BigInteger.valueOf(3)).add(BigInteger.valueOf((long) (intArray[i] + 1)));
        }
        int size = (BigInteger.valueOf(3).pow(intArray.length).bitLength() + 7) / 8;
        byte[] arr = sum.toByteArray();
        if (arr.length < size) {
            byte[] arr2 = new byte[size];
            System.arraycopy(arr, 0, arr2, size - arr.length, arr.length);
            return arr2;
        }
        if (arr.length > size) {
            arr = Arrays.copyOfRange(arr, 1, arr.length);
        }
        return arr;
    }

    public static int[] decodeMod3Tight(byte[] b, int N) {
        BigInteger sum = new BigInteger(1, b);
        int[] coeffs = new int[N];
        for (int i = 0; i < N; i++) {
            coeffs[i] = sum.mod(BigInteger.valueOf(3)).intValue() - 1;
            if (coeffs[i] > 1) {
                coeffs[i] = coeffs[i] - 3;
            }
            sum = sum.divide(BigInteger.valueOf(3));
        }
        return coeffs;
    }

    public static int[] decodeMod3Tight(InputStream is, int N) throws IOException {
        return decodeMod3Tight(Util.readFullLength(is, (int) Math.ceil(((((double) N) * Math.log(3.0d)) / Math.log(2.0d)) / 8.0d)), N);
    }

    private static int getBit(byte[] arr, int bitIndex) {
        return ((arr[bitIndex / 8] & 255) >> (bitIndex % 8)) & 1;
    }
}
