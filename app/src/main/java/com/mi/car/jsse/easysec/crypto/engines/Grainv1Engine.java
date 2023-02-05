package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.StreamCipher;
import com.mi.car.jsse.easysec.crypto.digests.Blake2xsDigest;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;

public class Grainv1Engine implements StreamCipher {
    private static final int STATE_SIZE = 5;
    private int index = 2;
    private boolean initialised = false;
    private int[] lfsr;
    private int[] nfsr;
    private byte[] out;
    private int output;
    private byte[] workingIV;
    private byte[] workingKey;

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public String getAlgorithmName() {
        return "Grain v1";
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        if (!(params instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("Grain v1 Init parameters must include an IV");
        }
        ParametersWithIV ivParams = (ParametersWithIV) params;
        byte[] iv = ivParams.getIV();
        if (iv == null || iv.length != 8) {
            throw new IllegalArgumentException("Grain v1 requires exactly 8 bytes of IV");
        } else if (!(ivParams.getParameters() instanceof KeyParameter)) {
            throw new IllegalArgumentException("Grain v1 Init parameters must include a key");
        } else {
            KeyParameter key = (KeyParameter) ivParams.getParameters();
            this.workingIV = new byte[key.getKey().length];
            this.workingKey = new byte[key.getKey().length];
            this.lfsr = new int[5];
            this.nfsr = new int[5];
            this.out = new byte[2];
            System.arraycopy(iv, 0, this.workingIV, 0, iv.length);
            System.arraycopy(key.getKey(), 0, this.workingKey, 0, key.getKey().length);
            reset();
        }
    }

    private void initGrain() {
        for (int i = 0; i < 10; i++) {
            this.output = getOutput();
            this.nfsr = shift(this.nfsr, (getOutputNFSR() ^ this.lfsr[0]) ^ this.output);
            this.lfsr = shift(this.lfsr, getOutputLFSR() ^ this.output);
        }
        this.initialised = true;
    }

    private int getOutputNFSR() {
        int b0 = this.nfsr[0];
        int b9 = (this.nfsr[0] >>> 9) | (this.nfsr[1] << 7);
        int b14 = (this.nfsr[0] >>> 14) | (this.nfsr[1] << 2);
        int b15 = (this.nfsr[0] >>> 15) | (this.nfsr[1] << 1);
        int b21 = (this.nfsr[1] >>> 5) | (this.nfsr[2] << 11);
        int b28 = (this.nfsr[1] >>> 12) | (this.nfsr[2] << 4);
        int b33 = (this.nfsr[2] >>> 1) | (this.nfsr[3] << 15);
        int b37 = (this.nfsr[2] >>> 5) | (this.nfsr[3] << 11);
        int b45 = (this.nfsr[2] >>> 13) | (this.nfsr[3] << 3);
        int b52 = (this.nfsr[3] >>> 4) | (this.nfsr[4] << 12);
        int b60 = (this.nfsr[3] >>> 12) | (this.nfsr[4] << 4);
        int b62 = (this.nfsr[3] >>> 14) | (this.nfsr[4] << 2);
        int b63 = (this.nfsr[3] >>> 15) | (this.nfsr[4] << 1);
        return (((((((((((((((((((((b62 ^ b60) ^ b52) ^ b45) ^ b37) ^ b33) ^ b28) ^ b21) ^ b14) ^ b9) ^ b0) ^ (b63 & b60)) ^ (b37 & b33)) ^ (b15 & b9)) ^ ((b60 & b52) & b45)) ^ ((b33 & b28) & b21)) ^ (((b63 & b45) & b28) & b9)) ^ (((b60 & b52) & b37) & b33)) ^ (((b63 & b60) & b21) & b15)) ^ ((((b63 & b60) & b52) & b45) & b37)) ^ ((((b33 & b28) & b21) & b15) & b9)) ^ (((((b52 & b45) & b37) & b33) & b28) & b21)) & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH;
    }

    private int getOutputLFSR() {
        int s0 = this.lfsr[0];
        int s13 = (this.lfsr[0] >>> 13) | (this.lfsr[1] << 3);
        int s23 = (this.lfsr[1] >>> 7) | (this.lfsr[2] << 9);
        int s38 = (this.lfsr[2] >>> 6) | (this.lfsr[3] << 10);
        int s51 = (this.lfsr[3] >>> 3) | (this.lfsr[4] << 13);
        return (((((s0 ^ s13) ^ s23) ^ s38) ^ s51) ^ ((this.lfsr[3] >>> 14) | (this.lfsr[4] << 2))) & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH;
    }

    private int getOutput() {
        int b1 = (this.nfsr[0] >>> 1) | (this.nfsr[1] << 15);
        int b2 = (this.nfsr[0] >>> 2) | (this.nfsr[1] << 14);
        int b4 = (this.nfsr[0] >>> 4) | (this.nfsr[1] << 12);
        int b10 = (this.nfsr[0] >>> 10) | (this.nfsr[1] << 6);
        int b31 = (this.nfsr[1] >>> 15) | (this.nfsr[2] << 1);
        int b43 = (this.nfsr[2] >>> 11) | (this.nfsr[3] << 5);
        int b56 = (this.nfsr[3] >>> 8) | (this.nfsr[4] << 8);
        int b63 = (this.nfsr[3] >>> 15) | (this.nfsr[4] << 1);
        int s3 = (this.lfsr[0] >>> 3) | (this.lfsr[1] << 13);
        int s25 = (this.lfsr[1] >>> 9) | (this.lfsr[2] << 7);
        int s46 = (this.lfsr[2] >>> 14) | (this.lfsr[3] << 2);
        int s64 = this.lfsr[4];
        return ((((((((((((((((s25 ^ b63) ^ (s3 & s64)) ^ (s46 & s64)) ^ (s64 & b63)) ^ ((s3 & s25) & s46)) ^ ((s3 & s46) & s64)) ^ ((s3 & s46) & b63)) ^ ((s25 & s46) & b63)) ^ ((s46 & s64) & b63)) ^ b1) ^ b2) ^ b4) ^ b10) ^ b31) ^ b43) ^ b56) & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH;
    }

    private int[] shift(int[] array, int val) {
        array[0] = array[1];
        array[1] = array[2];
        array[2] = array[3];
        array[3] = array[4];
        array[4] = val;
        return array;
    }

    private void setKey(byte[] keyBytes, byte[] ivBytes) {
        ivBytes[8] = -1;
        ivBytes[9] = -1;
        this.workingKey = keyBytes;
        this.workingIV = ivBytes;
        int j = 0;
        for (int i = 0; i < this.nfsr.length; i++) {
            this.nfsr[i] = ((this.workingKey[j + 1] << 8) | (this.workingKey[j] & 255)) & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH;
            this.lfsr[i] = ((this.workingIV[j + 1] << 8) | (this.workingIV[j] & 255)) & Blake2xsDigest.UNKNOWN_DIGEST_LENGTH;
            j += 2;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public int processBytes(byte[] in, int inOff, int len, byte[] out2, int outOff) throws DataLengthException {
        if (!this.initialised) {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        } else if (inOff + len > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (outOff + len > out2.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            for (int i = 0; i < len; i++) {
                out2[outOff + i] = (byte) (in[inOff + i] ^ getKeyStream());
            }
            return len;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public void reset() {
        this.index = 2;
        setKey(this.workingKey, this.workingIV);
        initGrain();
    }

    private void oneRound() {
        this.output = getOutput();
        this.out[0] = (byte) this.output;
        this.out[1] = (byte) (this.output >> 8);
        this.nfsr = shift(this.nfsr, getOutputNFSR() ^ this.lfsr[0]);
        this.lfsr = shift(this.lfsr, getOutputLFSR());
    }

    @Override // com.mi.car.jsse.easysec.crypto.StreamCipher
    public byte returnByte(byte in) {
        if (this.initialised) {
            return (byte) (getKeyStream() ^ in);
        }
        throw new IllegalStateException(getAlgorithmName() + " not initialised");
    }

    private byte getKeyStream() {
        if (this.index > 1) {
            oneRound();
            this.index = 0;
        }
        byte[] bArr = this.out;
        int i = this.index;
        this.index = i + 1;
        return bArr[i];
    }
}
