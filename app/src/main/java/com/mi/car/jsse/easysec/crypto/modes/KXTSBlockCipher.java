package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Pack;

public class KXTSBlockCipher extends BufferedBlockCipher {
    private static final long RED_POLY_128 = 135L;
    private static final long RED_POLY_256 = 1061L;
    private static final long RED_POLY_512 = 293L;
    private final int blockSize;
    private final long reductionPolynomial;
    private final long[] tw_init;
    private final long[] tw_current;
    private int counter;

    protected static long getReductionPolynomial(int blockSize) {
        switch(blockSize) {
            case 16:
                return 135L;
            case 32:
                return 1061L;
            case 64:
                return 293L;
            default:
                throw new IllegalArgumentException("Only 128, 256, and 512 -bit block sizes supported");
        }
    }

    public KXTSBlockCipher(BlockCipher cipher) {
        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();
        this.reductionPolynomial = getReductionPolynomial(this.blockSize);
        this.tw_init = new long[this.blockSize >>> 3];
        this.tw_current = new long[this.blockSize >>> 3];
        this.counter = -1;
    }

    public int getOutputSize(int length) {
        return length;
    }

    public int getUpdateOutputSize(int len) {
        return len;
    }

    public void init(boolean forEncryption, CipherParameters parameters) {
        if (!(parameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("Invalid parameters passed");
        } else {
            ParametersWithIV ivParam = (ParametersWithIV)parameters;
            parameters = ivParam.getParameters();
            byte[] iv = ivParam.getIV();
            if (iv.length != this.blockSize) {
                throw new IllegalArgumentException("Currently only support IVs of exactly one block");
            } else {
                byte[] tweak = new byte[this.blockSize];
                System.arraycopy(iv, 0, tweak, 0, this.blockSize);
                this.cipher.init(true, parameters);
                this.cipher.processBlock(tweak, 0, tweak, 0);
                this.cipher.init(forEncryption, parameters);
                Pack.littleEndianToLong(tweak, 0, this.tw_init);
                System.arraycopy(this.tw_init, 0, this.tw_current, 0, this.tw_init.length);
                this.counter = 0;
            }
        }
    }

    public int processByte(byte in, byte[] out, int outOff) {
        throw new IllegalStateException("unsupported operation");
    }

    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff) {
        if (input.length - inOff < len) {
            throw new DataLengthException("Input buffer too short");
        } else if (output.length - inOff < len) {
            throw new OutputLengthException("Output buffer too short");
        } else if (len % this.blockSize != 0) {
            throw new IllegalArgumentException("Partial blocks not supported");
        } else {
            for(int pos = 0; pos < len; pos += this.blockSize) {
                this.processBlock(input, inOff + pos, output, outOff + pos);
            }

            return len;
        }
    }

    private void processBlock(byte[] input, int inOff, byte[] output, int outOff) {
        if (this.counter == -1) {
            throw new IllegalStateException("Attempt to process too many blocks");
        } else {
            ++this.counter;
            GF_double(this.reductionPolynomial, this.tw_current);
            byte[] tweak = new byte[this.blockSize];
            Pack.longToLittleEndian(this.tw_current, tweak, 0);
            byte[] buffer = new byte[this.blockSize];
            System.arraycopy(tweak, 0, buffer, 0, this.blockSize);

            int i;
            for(i = 0; i < this.blockSize; ++i) {
                buffer[i] ^= input[inOff + i];
            }

            this.cipher.processBlock(buffer, 0, buffer, 0);

            for(i = 0; i < this.blockSize; ++i) {
                output[outOff + i] = (byte)(buffer[i] ^ tweak[i]);
            }

        }
    }

    public int doFinal(byte[] output, int outOff) {
        this.reset();
        return 0;
    }

    public void reset() {
        this.cipher.reset();
        System.arraycopy(this.tw_init, 0, this.tw_current, 0, this.tw_init.length);
        this.counter = 0;
    }

    private static void GF_double(long redPoly, long[] z) {
        long c = 0L;

        for(int i = 0; i < z.length; ++i) {
            long zVal = z[i];
            long bit = zVal >>> 63;
            z[i] = zVal << 1 ^ c;
            c = bit;
        }

        z[0] ^= redPoly & -c;
    }
}
