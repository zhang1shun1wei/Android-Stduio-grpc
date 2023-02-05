package com.mi.car.jsse.easysec.pqc.crypto.saber;

import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;

/* access modifiers changed from: package-private */
public class Utils {
    private final int SABER_EP;
    private final int SABER_ET;
    private final int SABER_KEYBYTES;
    private final int SABER_L;
    private final int SABER_N;
    private final int SABER_POLYBYTES;

    public Utils(SABEREngine engine) {
        this.SABER_N = engine.getSABER_N();
        this.SABER_L = engine.getSABER_L();
        this.SABER_ET = engine.getSABER_ET();
        this.SABER_POLYBYTES = engine.getSABER_POLYBYTES();
        this.SABER_EP = engine.getSABER_EP();
        this.SABER_KEYBYTES = engine.getSABER_KEYBYTES();
    }

    public void POLT2BS(byte[] bytes, int byteIndex, short[] data) {
        if (this.SABER_ET == 3) {
            for (short j = 0; j < this.SABER_N / 8; j = (short) (j + 1)) {
                short offset_byte = (short) (j * 3);
                short offset_data = (short) (j * 8);
                bytes[byteIndex + offset_byte + 0] = (byte) ((data[offset_data + 0] & 7) | ((data[offset_data + 1] & 7) << 3) | ((data[offset_data + 2] & 3) << 6));
                bytes[byteIndex + offset_byte + 1] = (byte) (((data[offset_data + 2] >> 2) & 1) | ((data[offset_data + 3] & 7) << 1) | ((data[offset_data + 4] & 7) << 4) | ((data[offset_data + 5] & 1) << 7));
                bytes[byteIndex + offset_byte + 2] = (byte) (((data[offset_data + 5] >> 1) & 3) | ((data[offset_data + 6] & 7) << 2) | ((data[offset_data + 7] & 7) << 5));
            }
        } else if (this.SABER_ET == 4) {
            for (short j2 = 0; j2 < this.SABER_N / 2; j2 = (short) (j2 + 1)) {
                short offset_data2 = (short) (j2 * 2);
                bytes[byteIndex + j2] = (byte) ((data[offset_data2] & 15) | ((data[offset_data2 + 1] & 15) << 4));
            }
        } else if (this.SABER_ET == 6) {
            for (short j3 = 0; j3 < this.SABER_N / 4; j3 = (short) (j3 + 1)) {
                short offset_byte2 = (short) (j3 * 3);
                short offset_data3 = (short) (j3 * 4);
                bytes[byteIndex + offset_byte2 + 0] = (byte) ((data[offset_data3 + 0] & 63) | ((data[offset_data3 + 1] & 3) << 6));
                bytes[byteIndex + offset_byte2 + 1] = (byte) (((data[offset_data3 + 1] >> 2) & 15) | ((data[offset_data3 + 2] & 15) << 4));
                bytes[byteIndex + offset_byte2 + 2] = (byte) (((data[offset_data3 + 2] >> 4) & 3) | ((data[offset_data3 + 3] & 63) << 2));
            }
        }
    }

    public void BS2POLT(byte[] bytes, int byteIndex, short[] data) {
        if (this.SABER_ET == 3) {
            for (short j = 0; j < this.SABER_N / 8; j = (short) (j + 1)) {
                short offset_byte = (short) (j * 3);
                short offset_data = (short) (j * 8);
                data[offset_data + 0] = (short) (bytes[byteIndex + offset_byte + 0] & 7);
                data[offset_data + 1] = (short) ((bytes[(byteIndex + offset_byte) + 0] >> 3) & 7);
                data[offset_data + 2] = (short) (((bytes[(byteIndex + offset_byte) + 0] >> 6) & 3) | ((bytes[(byteIndex + offset_byte) + 1] & 1) << 2));
                data[offset_data + 3] = (short) ((bytes[(byteIndex + offset_byte) + 1] >> 1) & 7);
                data[offset_data + 4] = (short) ((bytes[(byteIndex + offset_byte) + 1] >> 4) & 7);
                data[offset_data + 5] = (short) (((bytes[(byteIndex + offset_byte) + 1] >> 7) & 1) | ((bytes[(byteIndex + offset_byte) + 2] & 3) << 1));
                data[offset_data + 6] = (short) ((bytes[(byteIndex + offset_byte) + 2] >> 2) & 7);
                data[offset_data + 7] = (short) ((bytes[(byteIndex + offset_byte) + 2] >> 5) & 7);
            }
        } else if (this.SABER_ET == 4) {
            for (short j2 = 0; j2 < this.SABER_N / 2; j2 = (short) (j2 + 1)) {
                short offset_data2 = (short) (j2 * 2);
                data[offset_data2] = (short) (bytes[byteIndex + j2] & 15);
                data[offset_data2 + 1] = (short) ((bytes[byteIndex + j2] >> 4) & 15);
            }
        } else if (this.SABER_ET == 6) {
            for (short j3 = 0; j3 < this.SABER_N / 4; j3 = (short) (j3 + 1)) {
                short offset_byte2 = (short) (j3 * 3);
                short offset_data3 = (short) (j3 * 4);
                data[offset_data3 + 0] = (short) (bytes[byteIndex + offset_byte2 + 0] & 63);
                data[offset_data3 + 1] = (short) (((bytes[(byteIndex + offset_byte2) + 0] >> 6) & 3) | ((bytes[(byteIndex + offset_byte2) + 1] & 15) << 2));
                data[offset_data3 + 2] = (short) (((bytes[(byteIndex + offset_byte2) + 1] & 255) >> 4) | ((bytes[(byteIndex + offset_byte2) + 2] & 3) << 4));
                data[offset_data3 + 3] = (short) ((bytes[(byteIndex + offset_byte2) + 2] & 255) >> 2);
            }
        }
    }

    private void POLq2BS(byte[] bytes, int byteIndex, short[] data) {
        for (short j = 0; j < this.SABER_N / 8; j = (short) (j + 1)) {
            short offset_byte = (short) (j * 13);
            short offset_data = (short) (j * 8);
            bytes[byteIndex + offset_byte + 0] = (byte) (data[offset_data + 0] & 255);
            bytes[byteIndex + offset_byte + 1] = (byte) (((data[offset_data + 0] >> 8) & 31) | ((data[offset_data + 1] & 7) << 5));
            bytes[byteIndex + offset_byte + 2] = (byte) ((data[offset_data + 1] >> 3) & GF2Field.MASK);
            bytes[byteIndex + offset_byte + 3] = (byte) (((data[offset_data + 1] >> 11) & 3) | ((data[offset_data + 2] & 63) << 2));
            bytes[byteIndex + offset_byte + 4] = (byte) (((data[offset_data + 2] >> 6) & 127) | ((data[offset_data + 3] & 1) << 7));
            bytes[byteIndex + offset_byte + 5] = (byte) ((data[offset_data + 3] >> 1) & GF2Field.MASK);
            bytes[byteIndex + offset_byte + 6] = (byte) (((data[offset_data + 3] >> 9) & 15) | ((data[offset_data + 4] & 15) << 4));
            bytes[byteIndex + offset_byte + 7] = (byte) ((data[offset_data + 4] >> 4) & GF2Field.MASK);
            bytes[byteIndex + offset_byte + 8] = (byte) (((data[offset_data + 4] >> 12) & 1) | ((data[offset_data + 5] & 127) << 1));
            bytes[byteIndex + offset_byte + 9] = (byte) (((data[offset_data + 5] >> 7) & 63) | ((data[offset_data + 6] & 3) << 6));
            bytes[byteIndex + offset_byte + 10] = (byte) ((data[offset_data + 6] >> 2) & GF2Field.MASK);
            bytes[byteIndex + offset_byte + 11] = (byte) (((data[offset_data + 6] >> 10) & 7) | ((data[offset_data + 7] & 31) << 3));
            bytes[byteIndex + offset_byte + 12] = (byte) ((data[offset_data + 7] >> 5) & GF2Field.MASK);
        }
    }

    private void BS2POLq(byte[] bytes, int byteIndex, short[] data) {
        for (short j = 0; j < this.SABER_N / 8; j = (short) (j + 1)) {
            short offset_byte = (short) (j * 13);
            short offset_data = (short) (j * 8);
            data[offset_data + 0] = (short) ((bytes[byteIndex + offset_byte + 0] & 255) | ((bytes[(byteIndex + offset_byte) + 1] & 31) << 8));
            data[offset_data + 1] = (short) (((bytes[(byteIndex + offset_byte) + 1] >> 5) & 7) | ((bytes[(byteIndex + offset_byte) + 2] & 255) << 3) | ((bytes[(byteIndex + offset_byte) + 3] & 3) << 11));
            data[offset_data + 2] = (short) (((bytes[(byteIndex + offset_byte) + 3] >> 2) & 63) | ((bytes[(byteIndex + offset_byte) + 4] & Byte.MAX_VALUE) << 6));
            data[offset_data + 3] = (short) (((bytes[(byteIndex + offset_byte) + 4] >> 7) & 1) | ((bytes[(byteIndex + offset_byte) + 5] & 255) << 1) | ((bytes[(byteIndex + offset_byte) + 6] & 15) << 9));
            data[offset_data + 4] = (short) (((bytes[(byteIndex + offset_byte) + 6] >> 4) & 15) | ((bytes[(byteIndex + offset_byte) + 7] & 255) << 4) | ((bytes[(byteIndex + offset_byte) + 8] & 1) << 12));
            data[offset_data + 5] = (short) (((bytes[(byteIndex + offset_byte) + 8] >> 1) & 127) | ((bytes[(byteIndex + offset_byte) + 9] & 63) << 7));
            data[offset_data + 6] = (short) (((bytes[(byteIndex + offset_byte) + 9] >> 6) & 3) | ((bytes[(byteIndex + offset_byte) + 10] & 255) << 2) | ((bytes[(byteIndex + offset_byte) + 11] & 7) << 10));
            data[offset_data + 7] = (short) (((bytes[(byteIndex + offset_byte) + 11] >> 3) & 31) | ((bytes[(byteIndex + offset_byte) + 12] & 255) << 5));
        }
    }

    private void POLp2BS(byte[] bytes, int byteIndex, short[] data) {
        for (short j = 0; j < this.SABER_N / 4; j = (short) (j + 1)) {
            short offset_byte = (short) (j * 5);
            short offset_data = (short) (j * 4);
            bytes[byteIndex + offset_byte + 0] = (byte) (data[offset_data + 0] & 255);
            bytes[byteIndex + offset_byte + 1] = (byte) (((data[offset_data + 0] >> 8) & 3) | ((data[offset_data + 1] & 63) << 2));
            bytes[byteIndex + offset_byte + 2] = (byte) (((data[offset_data + 1] >> 6) & 15) | ((data[offset_data + 2] & 15) << 4));
            bytes[byteIndex + offset_byte + 3] = (byte) (((data[offset_data + 2] >> 4) & 63) | ((data[offset_data + 3] & 3) << 6));
            bytes[byteIndex + offset_byte + 4] = (byte) ((data[offset_data + 3] >> 2) & GF2Field.MASK);
        }
    }

    public void BS2POLp(byte[] bytes, int byteIndex, short[] data) {
        for (short j = 0; j < this.SABER_N / 4; j = (short) (j + 1)) {
            short offset_byte = (short) (j * 5);
            short offset_data = (short) (j * 4);
            data[offset_data + 0] = (short) ((bytes[byteIndex + offset_byte + 0] & 255) | ((bytes[(byteIndex + offset_byte) + 1] & 3) << 8));
            data[offset_data + 1] = (short) (((bytes[(byteIndex + offset_byte) + 1] >> 2) & 63) | ((bytes[(byteIndex + offset_byte) + 2] & 15) << 6));
            data[offset_data + 2] = (short) (((bytes[(byteIndex + offset_byte) + 2] >> 4) & 15) | ((bytes[(byteIndex + offset_byte) + 3] & 63) << 4));
            data[offset_data + 3] = (short) (((bytes[(byteIndex + offset_byte) + 3] >> 6) & 3) | ((bytes[(byteIndex + offset_byte) + 4] & 255) << 2));
        }
    }

    public void POLVECq2BS(byte[] bytes, short[][] data) {
        for (byte i = 0; i < this.SABER_L; i = (byte) (i + 1)) {
            POLq2BS(bytes, this.SABER_POLYBYTES * i, data[i]);
        }
    }

    public void BS2POLVECq(byte[] bytes, int byteIndex, short[][] data) {
        for (byte i = 0; i < this.SABER_L; i = (byte) (i + 1)) {
            BS2POLq(bytes, (this.SABER_POLYBYTES * i) + byteIndex, data[i]);
        }
    }

    public void POLVECp2BS(byte[] bytes, short[][] data) {
        for (byte i = 0; i < this.SABER_L; i = (byte) (i + 1)) {
            POLp2BS(bytes, ((this.SABER_EP * this.SABER_N) / 8) * i, data[i]);
        }
    }

    public void BS2POLVECp(byte[] bytes, short[][] data) {
        for (byte i = 0; i < this.SABER_L; i = (byte) (i + 1)) {
            BS2POLp(bytes, ((this.SABER_EP * this.SABER_N) / 8) * i, data[i]);
        }
    }

    public void BS2POLmsg(byte[] bytes, short[] data) {
        for (byte j = 0; j < this.SABER_KEYBYTES; j = (byte) (j + 1)) {
            for (byte i = 0; i < 8; i = (byte) (i + 1)) {
                data[(j * 8) + i] = (short) ((bytes[j] >> i) & 1);
            }
        }
    }

    public void POLmsg2BS(byte[] bytes, short[] data) {
        for (byte j = 0; j < this.SABER_KEYBYTES; j = (byte) (j + 1)) {
            for (byte i = 0; i < 8; i = (byte) (i + 1)) {
                bytes[j] = (byte) (bytes[j] | ((data[(j * 8) + i] & 1) << i));
            }
        }
    }
}
