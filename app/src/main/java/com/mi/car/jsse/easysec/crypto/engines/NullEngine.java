package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;

public class NullEngine implements BlockCipher {
    protected static final int DEFAULT_BLOCK_SIZE = 1;
    private final int blockSize;
    private boolean initialised;

    public NullEngine() {
        this(1);
    }

    public NullEngine(int blockSize2) {
        this.blockSize = blockSize2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        this.initialised = true;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "Null";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return this.blockSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (!this.initialised) {
            throw new IllegalStateException("Null engine not initialised");
        } else if (this.blockSize + inOff > in.length) {
            throw new DataLengthException("input buffer too short");
        } else if (this.blockSize + outOff > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            for (int i = 0; i < this.blockSize; i++) {
                out[outOff + i] = in[inOff + i];
            }
            return this.blockSize;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
    }
}
