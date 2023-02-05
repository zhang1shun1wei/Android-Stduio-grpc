package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.SkippingStreamCipher;
import com.mi.car.jsse.easysec.crypto.StreamBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

public class SICBlockCipher extends StreamBlockCipher implements SkippingStreamCipher {
    private final BlockCipher cipher;
    private final int blockSize;
    private byte[] IV;
    private byte[] counter;
    private byte[] counterOut;
    private int byteCount;

    public SICBlockCipher(BlockCipher c) {
        super(c);
        this.cipher = c;
        this.blockSize = this.cipher.getBlockSize();
        this.IV = new byte[this.blockSize];
        this.counter = new byte[this.blockSize];
        this.counterOut = new byte[this.blockSize];
        this.byteCount = 0;
    }

    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        if (params instanceof ParametersWithIV) {
            ParametersWithIV ivParam = (ParametersWithIV)params;
            this.IV = Arrays.clone(ivParam.getIV());
            if (this.blockSize < this.IV.length) {
                throw new IllegalArgumentException("CTR/SIC mode requires IV no greater than: " + this.blockSize + " bytes.");
            } else {
                int maxCounterSize = 8 > this.blockSize / 2 ? this.blockSize / 2 : 8;
                if (this.blockSize - this.IV.length > maxCounterSize) {
                    throw new IllegalArgumentException("CTR/SIC mode requires IV of at least: " + (this.blockSize - maxCounterSize) + " bytes.");
                } else {
                    if (ivParam.getParameters() != null) {
                        this.cipher.init(true, ivParam.getParameters());
                    }

                    this.reset();
                }
            }
        } else {
            throw new IllegalArgumentException("CTR/SIC mode requires ParametersWithIV");
        }
    }

    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/SIC";
    }

    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.byteCount != 0) {
            this.processBytes(in, inOff, this.blockSize, out, outOff);
            return this.blockSize;
        } else if (inOff + this.blockSize > in.length) {
            throw new DataLengthException("input buffer too small");
        } else if (outOff + this.blockSize > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            this.cipher.processBlock(this.counter, 0, this.counterOut, 0);

            for(int i = 0; i < this.blockSize; ++i) {
                out[outOff + i] = (byte)(in[inOff + i] ^ this.counterOut[i]);
            }

            this.incrementCounterChecked();
            return this.blockSize;
        }
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
        if (inOff + len > in.length) {
            throw new DataLengthException("input buffer too small");
        } else if (outOff + len > out.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            for(int i = 0; i < len; ++i) {
                byte next;
                if (this.byteCount == 0) {
                    this.cipher.processBlock(this.counter, 0, this.counterOut, 0);
                    next = (byte)(in[inOff + i] ^ this.counterOut[this.byteCount++]);
                } else {
                    next = (byte)(in[inOff + i] ^ this.counterOut[this.byteCount++]);
                    if (this.byteCount == this.counter.length) {
                        this.byteCount = 0;
                        this.incrementCounterChecked();
                    }
                }

                out[outOff + i] = next;
            }

            return len;
        }
    }

    public byte calculateByte(byte in) throws DataLengthException, IllegalStateException {
        if (this.byteCount == 0) {
            this.cipher.processBlock(this.counter, 0, this.counterOut, 0);
            return (byte)(this.counterOut[this.byteCount++] ^ in);
        } else {
            byte rv = (byte)(this.counterOut[this.byteCount++] ^ in);
            if (this.byteCount == this.counter.length) {
                this.byteCount = 0;
                this.incrementCounterChecked();
            }

            return rv;
        }
    }

    private void checkCounter() {
        if (this.IV.length < this.blockSize) {
            for(int i = 0; i != this.IV.length; ++i) {
                if (this.counter[i] != this.IV[i]) {
                    throw new IllegalStateException("Counter in CTR/SIC mode out of range.");
                }
            }
        }

    }

    private void incrementCounterChecked() {
        int i = this.counter.length;

        do {
            --i;
        } while(i >= 0 && ++this.counter[i] == 0);

        if (i < this.IV.length && this.IV.length < this.blockSize) {
            throw new IllegalStateException("Counter in CTR/SIC mode out of range.");
        }
    }

    private void incrementCounterAt(int pos) {
        int i = this.counter.length - pos;

        do {
            --i;
        } while(i >= 0 && ++this.counter[i] == 0);

    }

    private void incrementCounter(int offSet) {
        byte old = this.counter[this.counter.length - 1];
        byte[] var10000 = this.counter;
        int var10001 = this.counter.length - 1;
        var10000[var10001] = (byte)(var10000[var10001] + offSet);
        if (old != 0 && this.counter[this.counter.length - 1] < old) {
            this.incrementCounterAt(1);
        }

    }

    private void decrementCounterAt(int pos) {
        int i = this.counter.length - pos;

        do {
            --i;
            if (i < 0) {
                return;
            }
        } while(--this.counter[i] == -1);

    }

    private void adjustCounter(long n) {
        long numBlocks;
        long rem;
        int i;
        long diff;
        if (n >= 0L) {
            numBlocks = (n + (long)this.byteCount) / (long)this.blockSize;
            rem = numBlocks;
            if (numBlocks > 255L) {
                for(i = 5; i >= 1; --i) {
                    for(diff = 1L << 8 * i; rem >= diff; rem -= diff) {
                        this.incrementCounterAt(i);
                    }
                }
            }

            this.incrementCounter((int)rem);
            this.byteCount = (int)(n + (long)this.byteCount - (long)this.blockSize * numBlocks);
        } else {
            numBlocks = (-n - (long)this.byteCount) / (long)this.blockSize;
            rem = numBlocks;
            if (numBlocks > 255L) {
                for(i = 5; i >= 1; --i) {
                    for(diff = 1L << 8 * i; rem > diff; rem -= diff) {
                        this.decrementCounterAt(i);
                    }
                }
            }

            for(i = 0; i != rem; ++i) {
                this.decrementCounterAt(0);
            }

            i = (int)((long)this.byteCount + n + (long)this.blockSize * numBlocks);
            if (i >= 0) {
                this.byteCount = 0;
            } else {
                this.decrementCounterAt(0);
                this.byteCount = this.blockSize + i;
            }
        }

    }

    public void reset() {
        Arrays.fill(this.counter, (byte)0);
        System.arraycopy(this.IV, 0, this.counter, 0, this.IV.length);
        this.cipher.reset();
        this.byteCount = 0;
    }

    public long skip(long numberOfBytes) {
        this.adjustCounter(numberOfBytes);
        this.checkCounter();
        this.cipher.processBlock(this.counter, 0, this.counterOut, 0);
        return numberOfBytes;
    }

    public long seekTo(long position) {
        this.reset();
        return this.skip(position);
    }

    public long getPosition() {
        byte[] res = new byte[this.counter.length];
        System.arraycopy(this.counter, 0, res, 0, res.length);

        for(int i = res.length - 1; i >= 1; --i) {
            int v;
            if (i < this.IV.length) {
                v = (res[i] & 255) - (this.IV[i] & 255);
            } else {
                v = res[i] & 255;
            }

            if (v < 0) {
                --res[i - 1];
                v += 256;
            }

            res[i] = (byte)v;
        }

        return Pack.bigEndianToLong(res, res.length - 8) * (long)this.blockSize + (long)this.byteCount;
    }
}
