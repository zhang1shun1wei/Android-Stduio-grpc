package com.mi.car.jsse.easysec.crypto;

public class BufferedAsymmetricBlockCipher {
    protected byte[] buf;
    protected int bufOff;
    private final AsymmetricBlockCipher cipher;

    public BufferedAsymmetricBlockCipher(AsymmetricBlockCipher cipher2) {
        this.cipher = cipher2;
    }

    public AsymmetricBlockCipher getUnderlyingCipher() {
        return this.cipher;
    }

    public int getBufferPosition() {
        return this.bufOff;
    }

    public void init(boolean forEncryption, CipherParameters params) {
        int i;
        reset();
        this.cipher.init(forEncryption, params);
        int inputBlockSize = this.cipher.getInputBlockSize();
        if (forEncryption) {
            i = 1;
        } else {
            i = 0;
        }
        this.buf = new byte[(i + inputBlockSize)];
        this.bufOff = 0;
    }

    public int getInputBlockSize() {
        return this.cipher.getInputBlockSize();
    }

    public int getOutputBlockSize() {
        return this.cipher.getOutputBlockSize();
    }

    public void processByte(byte in) {
        if (this.bufOff >= this.buf.length) {
            throw new DataLengthException("attempt to process message too long for cipher");
        }
        byte[] bArr = this.buf;
        int i = this.bufOff;
        this.bufOff = i + 1;
        bArr[i] = in;
    }

    public void processBytes(byte[] in, int inOff, int len) {
        if (len != 0) {
            if (len < 0) {
                throw new IllegalArgumentException("Can't have a negative input length!");
            } else if (this.bufOff + len > this.buf.length) {
                throw new DataLengthException("attempt to process message too long for cipher");
            } else {
                System.arraycopy(in, inOff, this.buf, this.bufOff, len);
                this.bufOff += len;
            }
        }
    }

    public byte[] doFinal() throws InvalidCipherTextException {
        byte[] out = this.cipher.processBlock(this.buf, 0, this.bufOff);
        reset();
        return out;
    }

    public void reset() {
        if (this.buf != null) {
            for (int i = 0; i < this.buf.length; i++) {
                this.buf[i] = 0;
            }
        }
        this.bufOff = 0;
    }
}
