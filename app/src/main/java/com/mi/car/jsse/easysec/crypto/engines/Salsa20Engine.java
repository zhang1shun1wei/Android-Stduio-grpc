package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.MaxBytesExceededException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.SkippingStreamCipher;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Integers;
import com.mi.car.jsse.easysec.util.Pack;
import com.mi.car.jsse.easysec.util.Strings;

public class Salsa20Engine implements SkippingStreamCipher {
    public static final int DEFAULT_ROUNDS = 20;
    private static final int STATE_SIZE = 16;
    private static final int[] TAU_SIGMA = Pack.littleEndianToInt(Strings.toByteArray("expand 16-byte kexpand 32-byte k"), 0, 8);
    protected static final byte[] sigma = Strings.toByteArray("expand 32-byte k");
    protected static final byte[] tau = Strings.toByteArray("expand 16-byte k");
    private int cW0;
    private int cW1;
    private int cW2;
    protected int[] engineState;
    private int index;
    private boolean initialised;
    private byte[] keyStream;
    protected int rounds;
    protected int[] x;

    /* access modifiers changed from: protected */
    public void packTauOrSigma(int keyLength, int[] state, int stateOffset) {
        int tsOff = (keyLength - 16) / 4;
        state[stateOffset] = TAU_SIGMA[tsOff];
        state[stateOffset + 1] = TAU_SIGMA[tsOff + 1];
        state[stateOffset + 2] = TAU_SIGMA[tsOff + 2];
        state[stateOffset + 3] = TAU_SIGMA[tsOff + 3];
    }

    public Salsa20Engine() {
        this(20);
    }

    public Salsa20Engine(int rounds2) {
        this.index = 0;
        this.engineState = new int[16];
        this.x = new int[16];
        this.keyStream = new byte[64];
        this.initialised = false;
        if (rounds2 <= 0 || (rounds2 & 1) != 0) {
            throw new IllegalArgumentException("'rounds' must be a positive, even number");
        }
        this.rounds = rounds2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public void init(boolean forEncryption, CipherParameters params) {
        if (!(params instanceof ParametersWithIV)) {
            throw new IllegalArgumentException(getAlgorithmName() + " Init parameters must include an IV");
        }
        ParametersWithIV ivParams = (ParametersWithIV) params;
        byte[] iv = ivParams.getIV();
        if (iv == null || iv.length != getNonceSize()) {
            throw new IllegalArgumentException(getAlgorithmName() + " requires exactly " + getNonceSize() + " bytes of IV");
        }
        CipherParameters keyParam = ivParams.getParameters();
        if (keyParam == null) {
            if (!this.initialised) {
                throw new IllegalStateException(getAlgorithmName() + " KeyParameter can not be null for first initialisation");
            }
            setKey(null, iv);
        } else if (keyParam instanceof KeyParameter) {
            setKey(((KeyParameter) keyParam).getKey(), iv);
        } else {
            throw new IllegalArgumentException(getAlgorithmName() + " Init parameters must contain a KeyParameter (or null for re-init)");
        }
        reset();
        this.initialised = true;
    }

    /* access modifiers changed from: protected */
    public int getNonceSize() {
        return 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        if (this.rounds != 20) {
            return "Salsa20" + "/" + this.rounds;
        }
        return "Salsa20";
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public byte returnByte(byte in) {
        if (limitExceeded()) {
            throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
        }
        byte out = (byte) (this.keyStream[this.index] ^ in);
        this.index = (this.index + 1) & 63;
        if (this.index == 0) {
            advanceCounter();
            generateKeyStream(this.keyStream);
        }
        return out;
    }

    /* access modifiers changed from: protected */
    public void advanceCounter(long diff) {
        int hi = (int) (diff >>> 32);
        int lo = (int) diff;
        if (hi > 0) {
            int[] iArr = this.engineState;
            iArr[9] = iArr[9] + hi;
        }
        int oldState = this.engineState[8];
        int[] iArr2 = this.engineState;
        iArr2[8] = iArr2[8] + lo;
        if (oldState != 0 && this.engineState[8] < oldState) {
            int[] iArr3 = this.engineState;
            iArr3[9] = iArr3[9] + 1;
        }
    }

    /* access modifiers changed from: protected */
    public void advanceCounter() {
        int[] iArr = this.engineState;
        int i = iArr[8] + 1;
        iArr[8] = i;
        if (i == 0) {
            int[] iArr2 = this.engineState;
            iArr2[9] = iArr2[9] + 1;
        }
    }

    /* access modifiers changed from: protected */
    public void retreatCounter(long diff) {
        int hi = (int) (diff >>> 32);
        int lo = (int) diff;
        if (hi != 0) {
            if ((((long) this.engineState[9]) & 4294967295L) >= (((long) hi) & 4294967295L)) {
                int[] iArr = this.engineState;
                iArr[9] = iArr[9] - hi;
            } else {
                throw new IllegalStateException("attempt to reduce counter past zero.");
            }
        }
        if ((((long) this.engineState[8]) & 4294967295L) >= (((long) lo) & 4294967295L)) {
            int[] iArr2 = this.engineState;
            iArr2[8] = iArr2[8] - lo;
        } else if (this.engineState[9] != 0) {
            int[] iArr3 = this.engineState;
            iArr3[9] = iArr3[9] - 1;
            int[] iArr4 = this.engineState;
            iArr4[8] = iArr4[8] - lo;
        } else {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }
    }

    /* access modifiers changed from: protected */
    public void retreatCounter() {
        if (this.engineState[8] == 0 && this.engineState[9] == 0) {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }
        int[] iArr = this.engineState;
        int i = iArr[8] - 1;
        iArr[8] = i;
        if (i == -1) {
            int[] iArr2 = this.engineState;
            iArr2[9] = iArr2[9] - 1;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) {
        if (!this.initialised) {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        } else if (inOff + len > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (outOff + len > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else if (limitExceeded(len)) {
            throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
        } else {
            for (int i = 0; i < len; i++) {
                out[i + outOff] = (byte) (this.keyStream[this.index] ^ in[i + inOff]);
                this.index = (this.index + 1) & 63;
                if (this.index == 0) {
                    advanceCounter();
                    generateKeyStream(this.keyStream);
                }
            }
            return len;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.SkippingCipher
    public long skip(long numberOfBytes) {
        if (numberOfBytes >= 0) {
            long remaining = numberOfBytes;
            if (remaining >= 64) {
                long count = remaining / 64;
                advanceCounter(count);
                remaining -= count * 64;
            }
            int oldIndex = this.index;
            this.index = (this.index + ((int) remaining)) & 63;
            if (this.index < oldIndex) {
                advanceCounter();
            }
        } else {
            long remaining2 = -numberOfBytes;
            if (remaining2 >= 64) {
                long count2 = remaining2 / 64;
                retreatCounter(count2);
                remaining2 -= count2 * 64;
            }
            for (long i = 0; i < remaining2; i++) {
                if (this.index == 0) {
                    retreatCounter();
                }
                this.index = (this.index - 1) & 63;
            }
        }
        generateKeyStream(this.keyStream);
        return numberOfBytes;
    }

    @Override // com.mi.car.jsse.easysec.crypto.SkippingCipher
    public long seekTo(long position) {
        reset();
        return skip(position);
    }

    @Override // com.mi.car.jsse.easysec.crypto.SkippingCipher
    public long getPosition() {
        return (getCounter() * 64) + ((long) this.index);
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public void reset() {
        this.index = 0;
        resetLimitCounter();
        resetCounter();
        generateKeyStream(this.keyStream);
    }

    /* access modifiers changed from: protected */
    public long getCounter() {
        return (((long) this.engineState[9]) << 32) | (((long) this.engineState[8]) & 4294967295L);
    }

    /* access modifiers changed from: protected */
    public void resetCounter() {
        int[] iArr = this.engineState;
        this.engineState[9] = 0;
        iArr[8] = 0;
    }

    /* access modifiers changed from: protected */
    public void setKey(byte[] keyBytes, byte[] ivBytes) {
        if (keyBytes != null) {
            if (keyBytes.length == 16 || keyBytes.length == 32) {
                int tsOff = (keyBytes.length - 16) / 4;
                this.engineState[0] = TAU_SIGMA[tsOff];
                this.engineState[5] = TAU_SIGMA[tsOff + 1];
                this.engineState[10] = TAU_SIGMA[tsOff + 2];
                this.engineState[15] = TAU_SIGMA[tsOff + 3];
                Pack.littleEndianToInt(keyBytes, 0, this.engineState, 1, 4);
                Pack.littleEndianToInt(keyBytes, keyBytes.length - 16, this.engineState, 11, 4);
            } else {
                throw new IllegalArgumentException(getAlgorithmName() + " requires 128 bit or 256 bit key");
            }
        }
        Pack.littleEndianToInt(ivBytes, 0, this.engineState, 6, 2);
    }

    /* access modifiers changed from: protected */
    public void generateKeyStream(byte[] output) {
        salsaCore(this.rounds, this.engineState, this.x);
        Pack.intToLittleEndian(this.x, output, 0);
    }

    public static void salsaCore(int rounds2, int[] input, int[] x2) {
        if (input.length != 16) {
            throw new IllegalArgumentException();
        } else if (x2.length != 16) {
            throw new IllegalArgumentException();
        } else if (rounds2 % 2 != 0) {
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
            for (int i = rounds2; i > 0; i -= 2) {
                int x042 = x04 ^ Integers.rotateLeft(x00 + x12, 7);
                int x082 = x08 ^ Integers.rotateLeft(x042 + x00, 9);
                int x122 = x12 ^ Integers.rotateLeft(x082 + x042, 13);
                int x002 = x00 ^ Integers.rotateLeft(x122 + x082, 18);
                int x092 = x09 ^ Integers.rotateLeft(x05 + x01, 7);
                int x132 = x13 ^ Integers.rotateLeft(x092 + x05, 9);
                int x012 = x01 ^ Integers.rotateLeft(x132 + x092, 13);
                int x052 = x05 ^ Integers.rotateLeft(x012 + x132, 18);
                int x142 = x14 ^ Integers.rotateLeft(x10 + x06, 7);
                int x022 = x02 ^ Integers.rotateLeft(x142 + x10, 9);
                int x062 = x06 ^ Integers.rotateLeft(x022 + x142, 13);
                int x102 = x10 ^ Integers.rotateLeft(x062 + x022, 18);
                int x032 = x03 ^ Integers.rotateLeft(x15 + x11, 7);
                int x072 = x07 ^ Integers.rotateLeft(x032 + x15, 9);
                int x112 = x11 ^ Integers.rotateLeft(x072 + x032, 13);
                int x152 = x15 ^ Integers.rotateLeft(x112 + x072, 18);
                x01 = x012 ^ Integers.rotateLeft(x002 + x032, 7);
                x02 = x022 ^ Integers.rotateLeft(x01 + x002, 9);
                x03 = x032 ^ Integers.rotateLeft(x02 + x01, 13);
                x00 = x002 ^ Integers.rotateLeft(x03 + x02, 18);
                x06 = x062 ^ Integers.rotateLeft(x052 + x042, 7);
                x07 = x072 ^ Integers.rotateLeft(x06 + x052, 9);
                x04 = x042 ^ Integers.rotateLeft(x07 + x06, 13);
                x05 = x052 ^ Integers.rotateLeft(x04 + x07, 18);
                x11 = x112 ^ Integers.rotateLeft(x102 + x092, 7);
                x08 = x082 ^ Integers.rotateLeft(x11 + x102, 9);
                x09 = x092 ^ Integers.rotateLeft(x08 + x11, 13);
                x10 = x102 ^ Integers.rotateLeft(x09 + x08, 18);
                x12 = x122 ^ Integers.rotateLeft(x152 + x142, 7);
                x13 = x132 ^ Integers.rotateLeft(x12 + x152, 9);
                x14 = x142 ^ Integers.rotateLeft(x13 + x12, 13);
                x15 = x152 ^ Integers.rotateLeft(x14 + x13, 18);
            }
            x2[0] = input[0] + x00;
            x2[1] = input[1] + x01;
            x2[2] = input[2] + x02;
            x2[3] = input[3] + x03;
            x2[4] = input[4] + x04;
            x2[5] = input[5] + x05;
            x2[6] = input[6] + x06;
            x2[7] = input[7] + x07;
            x2[8] = input[8] + x08;
            x2[9] = input[9] + x09;
            x2[10] = input[10] + x10;
            x2[11] = input[11] + x11;
            x2[12] = input[12] + x12;
            x2[13] = input[13] + x13;
            x2[14] = input[14] + x14;
            x2[15] = input[15] + x15;
        }
    }

    private void resetLimitCounter() {
        this.cW0 = 0;
        this.cW1 = 0;
        this.cW2 = 0;
    }

    private boolean limitExceeded() {
        int i = this.cW0 + 1;
        this.cW0 = i;
        if (i != 0) {
            return false;
        }
        int i2 = this.cW1 + 1;
        this.cW1 = i2;
        if (i2 != 0) {
            return false;
        }
        int i3 = this.cW2 + 1;
        this.cW2 = i3;
        if ((i3 & 32) != 0) {
            return true;
        }
        return false;
    }

    private boolean limitExceeded(int len) {
        this.cW0 += len;
        if (this.cW0 >= len || this.cW0 < 0) {
            return false;
        }
        int i = this.cW1 + 1;
        this.cW1 = i;
        if (i != 0) {
            return false;
        }
        int i2 = this.cW2 + 1;
        this.cW2 = i2;
        if ((i2 & 32) != 0) {
            return true;
        }
        return false;
    }
}
