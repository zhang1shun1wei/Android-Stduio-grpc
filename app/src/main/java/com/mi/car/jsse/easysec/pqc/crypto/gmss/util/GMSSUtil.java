package com.mi.car.jsse.easysec.pqc.crypto.gmss.util;

import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;

public class GMSSUtil {
    public byte[] intToBytesLittleEndian(int value) {
        return new byte[]{(byte) (value & GF2Field.MASK), (byte) ((value >> 8) & GF2Field.MASK), (byte) ((value >> 16) & GF2Field.MASK), (byte) ((value >> 24) & GF2Field.MASK)};
    }

    public int bytesToIntLittleEndian(byte[] bytes) {
        return (bytes[0] & 255) | ((bytes[1] & 255) << 8) | ((bytes[2] & 255) << 16) | ((bytes[3] & 255) << 24);
    }

    public int bytesToIntLittleEndian(byte[] bytes, int offset) {
        int offset2 = offset + 1;
        int offset3 = offset2 + 1;
        return (bytes[offset] & 255) | ((bytes[offset2] & 255) << 8) | ((bytes[offset3] & 255) << 16) | ((bytes[offset3 + 1] & 255) << 24);
    }

    public byte[] concatenateArray(byte[][] arraycp) {
        byte[] dest = new byte[(arraycp.length * arraycp[0].length)];
        int indx = 0;
        for (int i = 0; i < arraycp.length; i++) {
            System.arraycopy(arraycp[i], 0, dest, indx, arraycp[i].length);
            indx += arraycp[i].length;
        }
        return dest;
    }

    public void printArray(String text, byte[][] array) {
        System.out.println(text);
        int counter = 0;
        for (int i = 0; i < array.length; i++) {
            for (int j = 0; j < array[0].length; j++) {
                System.out.println(counter + "; " + ((int) array[i][j]));
                counter++;
            }
        }
    }

    public void printArray(String text, byte[] array) {
        System.out.println(text);
        int counter = 0;
        for (int i = 0; i < array.length; i++) {
            System.out.println(counter + "; " + ((int) array[i]));
            counter++;
        }
    }

    public boolean testPowerOfTwo(int testValue) {
        int a = 1;
        while (a < testValue) {
            a <<= 1;
        }
        if (testValue == a) {
            return true;
        }
        return false;
    }

    public int getLog(int intValue) {
        int log = 1;
        int i = 2;
        while (i < intValue) {
            i <<= 1;
            log++;
        }
        return log;
    }
}
