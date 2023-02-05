package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.util.Integers;
import com.mi.car.jsse.easysec.util.Pack;

public class ChaChaEngine extends Salsa20Engine {
    public ChaChaEngine() {
    }

    public ChaChaEngine(int rounds) {
        super(rounds);
    }

    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine, com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        return "ChaCha" + this.rounds;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void advanceCounter(long diff) {
        int hi = (int) (diff >>> 32);
        int lo = (int) diff;
        if (hi > 0) {
            int[] iArr = this.engineState;
            iArr[13] = iArr[13] + hi;
        }
        int oldState = this.engineState[12];
        int[] iArr2 = this.engineState;
        iArr2[12] = iArr2[12] + lo;
        if (oldState != 0 && this.engineState[12] < oldState) {
            int[] iArr3 = this.engineState;
            iArr3[13] = iArr3[13] + 1;
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void advanceCounter() {
        int[] iArr = this.engineState;
        int i = iArr[12] + 1;
        iArr[12] = i;
        if (i == 0) {
            int[] iArr2 = this.engineState;
            iArr2[13] = iArr2[13] + 1;
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void retreatCounter(long diff) {
        int hi = (int) (diff >>> 32);
        int lo = (int) diff;
        if (hi != 0) {
            if ((((long) this.engineState[13]) & 4294967295L) >= (((long) hi) & 4294967295L)) {
                int[] iArr = this.engineState;
                iArr[13] = iArr[13] - hi;
            } else {
                throw new IllegalStateException("attempt to reduce counter past zero.");
            }
        }
        if ((((long) this.engineState[12]) & 4294967295L) >= (((long) lo) & 4294967295L)) {
            int[] iArr2 = this.engineState;
            iArr2[12] = iArr2[12] - lo;
        } else if (this.engineState[13] != 0) {
            int[] iArr3 = this.engineState;
            iArr3[13] = iArr3[13] - 1;
            int[] iArr4 = this.engineState;
            iArr4[12] = iArr4[12] - lo;
        } else {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void retreatCounter() {
        if (this.engineState[12] == 0 && this.engineState[13] == 0) {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }
        int[] iArr = this.engineState;
        int i = iArr[12] - 1;
        iArr[12] = i;
        if (i == -1) {
            int[] iArr2 = this.engineState;
            iArr2[13] = iArr2[13] - 1;
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public long getCounter() {
        return (((long) this.engineState[13]) << 32) | (((long) this.engineState[12]) & 4294967295L);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void resetCounter() {
        int[] iArr = this.engineState;
        this.engineState[13] = 0;
        iArr[12] = 0;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void setKey(byte[] keyBytes, byte[] ivBytes) {
        if (keyBytes != null) {
            if (keyBytes.length == 16 || keyBytes.length == 32) {
                packTauOrSigma(keyBytes.length, this.engineState, 0);
                Pack.littleEndianToInt(keyBytes, 0, this.engineState, 4, 4);
                Pack.littleEndianToInt(keyBytes, keyBytes.length - 16, this.engineState, 8, 4);
            } else {
                throw new IllegalArgumentException(getAlgorithmName() + " requires 128 bit or 256 bit key");
            }
        }
        Pack.littleEndianToInt(ivBytes, 0, this.engineState, 14, 2);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.Salsa20Engine
    public void generateKeyStream(byte[] output) {
        chachaCore(this.rounds, this.engineState, this.x);
        Pack.intToLittleEndian(this.x, output, 0);
    }

    public static void chachaCore(int rounds, int[] input, int[] x) {
        if (input.length != 16) {
            throw new IllegalArgumentException();
        } else if (x.length != 16) {
            throw new IllegalArgumentException();
        } else if (rounds % 2 != 0) {
            throw new IllegalArgumentException("Number of rounds must be even");
        } else {
            int x00 = input[0];
            int x01 = input[1];
            int x02 = input[2];
            int x03 = input[3];
            int x04 = input[4];
            int x05 = input[5];
            int x06 = input[6];
            int x07 = input[7];
            int x08 = input[8];
            int x09 = input[9];
            int x10 = input[10];
            int x11 = input[11];
            int x12 = input[12];
            int x13 = input[13];
            int x14 = input[14];
            int x15 = input[15];
            for (int i = rounds; i > 0; i -= 2) {
                int x002 = x00 + x04;
                int x122 = Integers.rotateLeft(x12 ^ x002, 16);
                int x082 = x08 + x122;
                int x042 = Integers.rotateLeft(x04 ^ x082, 12);
                int x003 = x002 + x042;
                int x123 = Integers.rotateLeft(x122 ^ x003, 8);
                int x083 = x082 + x123;
                int x043 = Integers.rotateLeft(x042 ^ x083, 7);
                int x012 = x01 + x05;
                int x132 = Integers.rotateLeft(x13 ^ x012, 16);
                int x092 = x09 + x132;
                int x052 = Integers.rotateLeft(x05 ^ x092, 12);
                int x013 = x012 + x052;
                int x133 = Integers.rotateLeft(x132 ^ x013, 8);
                int x093 = x092 + x133;
                int x053 = Integers.rotateLeft(x052 ^ x093, 7);
                int x022 = x02 + x06;
                int x142 = Integers.rotateLeft(x14 ^ x022, 16);
                int x102 = x10 + x142;
                int x062 = Integers.rotateLeft(x06 ^ x102, 12);
                int x023 = x022 + x062;
                int x143 = Integers.rotateLeft(x142 ^ x023, 8);
                int x103 = x102 + x143;
                int x063 = Integers.rotateLeft(x062 ^ x103, 7);
                int x032 = x03 + x07;
                int x152 = Integers.rotateLeft(x15 ^ x032, 16);
                int x112 = x11 + x152;
                int x072 = Integers.rotateLeft(x07 ^ x112, 12);
                int x033 = x032 + x072;
                int x153 = Integers.rotateLeft(x152 ^ x033, 8);
                int x113 = x112 + x153;
                int x073 = Integers.rotateLeft(x072 ^ x113, 7);
                int x004 = x003 + x053;
                int x154 = Integers.rotateLeft(x153 ^ x004, 16);
                int x104 = x103 + x154;
                int x054 = Integers.rotateLeft(x053 ^ x104, 12);
                x00 = x004 + x054;
                x15 = Integers.rotateLeft(x154 ^ x00, 8);
                x10 = x104 + x15;
                x05 = Integers.rotateLeft(x054 ^ x10, 7);
                int x014 = x013 + x063;
                int x124 = Integers.rotateLeft(x123 ^ x014, 16);
                int x114 = x113 + x124;
                int x064 = Integers.rotateLeft(x063 ^ x114, 12);
                x01 = x014 + x064;
                x12 = Integers.rotateLeft(x124 ^ x01, 8);
                x11 = x114 + x12;
                x06 = Integers.rotateLeft(x064 ^ x11, 7);
                int x024 = x023 + x073;
                int x134 = Integers.rotateLeft(x133 ^ x024, 16);
                int x084 = x083 + x134;
                int x074 = Integers.rotateLeft(x073 ^ x084, 12);
                x02 = x024 + x074;
                x13 = Integers.rotateLeft(x134 ^ x02, 8);
                x08 = x084 + x13;
                x07 = Integers.rotateLeft(x074 ^ x08, 7);
                int x034 = x033 + x043;
                int x144 = Integers.rotateLeft(x143 ^ x034, 16);
                int x094 = x093 + x144;
                int x044 = Integers.rotateLeft(x043 ^ x094, 12);
                x03 = x034 + x044;
                x14 = Integers.rotateLeft(x144 ^ x03, 8);
                x09 = x094 + x14;
                x04 = Integers.rotateLeft(x044 ^ x09, 7);
            }
            x[0] = input[0] + x00;
            x[1] = input[1] + x01;
            x[2] = input[2] + x02;
            x[3] = input[3] + x03;
            x[4] = input[4] + x04;
            x[5] = input[5] + x05;
            x[6] = input[6] + x06;
            x[7] = input[7] + x07;
            x[8] = input[8] + x08;
            x[9] = input[9] + x09;
            x[10] = input[10] + x10;
            x[11] = input[11] + x11;
            x[12] = input[12] + x12;
            x[13] = input[13] + x13;
            x[14] = input[14] + x14;
            x[15] = input[15] + x15;
        }
    }
}
