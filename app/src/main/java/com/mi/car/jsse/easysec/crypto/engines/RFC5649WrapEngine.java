package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.Wrapper;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

public class RFC5649WrapEngine implements Wrapper {
    private BlockCipher engine;
    private byte[] extractedAIV = null;
    private boolean forWrapping;
    private byte[] highOrderIV = {-90, 89, 89, -90};
    private KeyParameter param;
    private byte[] preIV = this.highOrderIV;

    public RFC5649WrapEngine(BlockCipher engine2) {
        this.engine = engine2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Wrapper
    public void init(boolean forWrapping2, CipherParameters param2) {
        this.forWrapping = forWrapping2;
        if (param2 instanceof ParametersWithRandom) {
            param2 = ((ParametersWithRandom) param2).getParameters();
        }
        if (param2 instanceof KeyParameter) {
            this.param = (KeyParameter) param2;
            this.preIV = this.highOrderIV;
        } else if (param2 instanceof ParametersWithIV) {
            this.preIV = ((ParametersWithIV) param2).getIV();
            this.param = (KeyParameter) ((ParametersWithIV) param2).getParameters();
            if (this.preIV.length != 4) {
                throw new IllegalArgumentException("IV length not equal to 4");
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Wrapper
    public String getAlgorithmName() {
        return this.engine.getAlgorithmName();
    }

    private byte[] padPlaintext(byte[] plaintext) {
        int plaintextLength = plaintext.length;
        int numOfZerosToAppend = (8 - (plaintextLength % 8)) % 8;
        byte[] paddedPlaintext = new byte[(plaintextLength + numOfZerosToAppend)];
        System.arraycopy(plaintext, 0, paddedPlaintext, 0, plaintextLength);
        if (numOfZerosToAppend != 0) {
            System.arraycopy(new byte[numOfZerosToAppend], 0, paddedPlaintext, plaintextLength, numOfZerosToAppend);
        }
        return paddedPlaintext;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Wrapper
    public byte[] wrap(byte[] in, int inOff, int inLen) {
        if (!this.forWrapping) {
            throw new IllegalStateException("not set for wrapping");
        }
        byte[] iv = new byte[8];
        byte[] mli = Pack.intToBigEndian(inLen);
        System.arraycopy(this.preIV, 0, iv, 0, this.preIV.length);
        System.arraycopy(mli, 0, iv, this.preIV.length, mli.length);
        byte[] relevantPlaintext = new byte[inLen];
        System.arraycopy(in, inOff, relevantPlaintext, 0, inLen);
        byte[] paddedPlaintext = padPlaintext(relevantPlaintext);
        if (paddedPlaintext.length == 8) {
            byte[] paddedPlainTextWithIV = new byte[(paddedPlaintext.length + iv.length)];
            System.arraycopy(iv, 0, paddedPlainTextWithIV, 0, iv.length);
            System.arraycopy(paddedPlaintext, 0, paddedPlainTextWithIV, iv.length, paddedPlaintext.length);
            this.engine.init(true, this.param);
            int i = 0;
            while (i < paddedPlainTextWithIV.length) {
                this.engine.processBlock(paddedPlainTextWithIV, i, paddedPlainTextWithIV, i);
                i += this.engine.getBlockSize();
            }
            return paddedPlainTextWithIV;
        }
        Wrapper wrapper = new RFC3394WrapEngine(this.engine);
        wrapper.init(true, new ParametersWithIV(this.param, iv));
        return wrapper.wrap(paddedPlaintext, 0, paddedPlaintext.length);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Wrapper
    public byte[] unwrap(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        byte[] paddedPlaintext;
        if (this.forWrapping) {
            throw new IllegalStateException("not set for unwrapping");
        }
        int n = inLen / 8;
        if (n * 8 != inLen) {
            throw new InvalidCipherTextException("unwrap data must be a multiple of 8 bytes");
        } else if (n <= 1) {
            throw new InvalidCipherTextException("unwrap data must be at least 16 bytes");
        } else {
            byte[] relevantCiphertext = new byte[inLen];
            System.arraycopy(in, inOff, relevantCiphertext, 0, inLen);
            byte[] decrypted = new byte[inLen];
            if (n == 2) {
                this.engine.init(false, this.param);
                int i = 0;
                while (i < relevantCiphertext.length) {
                    this.engine.processBlock(relevantCiphertext, i, decrypted, i);
                    i += this.engine.getBlockSize();
                }
                this.extractedAIV = new byte[8];
                System.arraycopy(decrypted, 0, this.extractedAIV, 0, this.extractedAIV.length);
                paddedPlaintext = new byte[(decrypted.length - this.extractedAIV.length)];
                System.arraycopy(decrypted, this.extractedAIV.length, paddedPlaintext, 0, paddedPlaintext.length);
            } else {
                paddedPlaintext = rfc3394UnwrapNoIvCheck(in, inOff, inLen);
            }
            byte[] extractedHighOrderAIV = new byte[4];
            byte[] mliBytes = new byte[4];
            System.arraycopy(this.extractedAIV, 0, extractedHighOrderAIV, 0, extractedHighOrderAIV.length);
            System.arraycopy(this.extractedAIV, extractedHighOrderAIV.length, mliBytes, 0, mliBytes.length);
            int mli = Pack.bigEndianToInt(mliBytes, 0);
            boolean isValid = true;
            if (!Arrays.constantTimeAreEqual(extractedHighOrderAIV, this.preIV)) {
                isValid = false;
            }
            int upperBound = paddedPlaintext.length;
            if (mli <= upperBound - 8) {
                isValid = false;
            }
            if (mli > upperBound) {
                isValid = false;
            }
            int expectedZeros = upperBound - mli;
            if (expectedZeros >= 8 || expectedZeros < 0) {
                isValid = false;
                expectedZeros = 4;
            }
            byte[] pad = new byte[expectedZeros];
            System.arraycopy(paddedPlaintext, paddedPlaintext.length - expectedZeros, pad, 0, expectedZeros);
            if (!Arrays.constantTimeAreEqual(pad, new byte[expectedZeros])) {
                isValid = false;
            }
            if (!isValid) {
                throw new InvalidCipherTextException("checksum failed");
            }
            byte[] plaintext = new byte[mli];
            System.arraycopy(paddedPlaintext, 0, plaintext, 0, plaintext.length);
            return plaintext;
        }
    }

    private byte[] rfc3394UnwrapNoIvCheck(byte[] in, int inOff, int inLen) {
        byte[] iv = new byte[8];
        byte[] block = new byte[(inLen - iv.length)];
        byte[] a = new byte[iv.length];
        byte[] buf = new byte[(iv.length + 8)];
        System.arraycopy(in, inOff, a, 0, iv.length);
        System.arraycopy(in, iv.length + inOff, block, 0, inLen - iv.length);
        this.engine.init(false, this.param);
        int n = (inLen / 8) - 1;
        for (int j = 5; j >= 0; j--) {
            for (int i = n; i >= 1; i--) {
                System.arraycopy(a, 0, buf, 0, iv.length);
                System.arraycopy(block, (i - 1) * 8, buf, iv.length, 8);
                int t = (n * j) + i;
                int k = 1;
                while (t != 0) {
                    int length = iv.length - k;
                    buf[length] = (byte) (buf[length] ^ ((byte) t));
                    t >>>= 8;
                    k++;
                }
                this.engine.processBlock(buf, 0, buf, 0);
                System.arraycopy(buf, 0, a, 0, 8);
                System.arraycopy(buf, 8, block, (i - 1) * 8, 8);
            }
        }
        this.extractedAIV = a;
        return block;
    }
}
