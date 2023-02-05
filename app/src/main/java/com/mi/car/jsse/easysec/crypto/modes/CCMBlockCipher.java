package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.macs.CBCBlockCipherMac;
import com.mi.car.jsse.easysec.crypto.params.AEADParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayOutputStream;

public class CCMBlockCipher implements AEADBlockCipher {
    private ExposedByteArrayOutputStream associatedText = new ExposedByteArrayOutputStream();
    private int blockSize;
    private BlockCipher cipher;
    private ExposedByteArrayOutputStream data = new ExposedByteArrayOutputStream();
    private boolean forEncryption;
    private byte[] initialAssociatedText;
    private CipherParameters keyParam;
    private byte[] macBlock;
    private int macSize;
    private byte[] nonce;

    public CCMBlockCipher(BlockCipher c) {
        this.cipher = c;
        this.blockSize = c.getBlockSize();
        this.macBlock = new byte[this.blockSize];
        if (this.blockSize != 16) {
            throw new IllegalArgumentException("cipher required with a block size of 16.");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher
    public BlockCipher getUnderlyingCipher() {
        return this.cipher;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void init(boolean forEncryption2, CipherParameters params) throws IllegalArgumentException {
        CipherParameters cipherParameters;
        this.forEncryption = forEncryption2;
        if (params instanceof AEADParameters) {
            AEADParameters param = (AEADParameters) params;
            this.nonce = param.getNonce();
            this.initialAssociatedText = param.getAssociatedText();
            this.macSize = getMacSize(forEncryption2, param.getMacSize());
            cipherParameters = param.getKey();
        } else if (params instanceof ParametersWithIV) {
            ParametersWithIV param2 = (ParametersWithIV) params;
            this.nonce = param2.getIV();
            this.initialAssociatedText = null;
            this.macSize = getMacSize(forEncryption2, 64);
            cipherParameters = param2.getParameters();
        } else {
            throw new IllegalArgumentException("invalid parameters passed to CCM: " + params.getClass().getName());
        }
        if (cipherParameters != null) {
            this.keyParam = cipherParameters;
        }
        if (this.nonce == null || this.nonce.length < 7 || this.nonce.length > 13) {
            throw new IllegalArgumentException("nonce must have length from 7 to 13 octets");
        }
        reset();
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/CCM";
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void processAADByte(byte in) {
        this.associatedText.write(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void processAADBytes(byte[] in, int inOff, int len) {
        this.associatedText.write(in, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int processByte(byte in, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        this.data.write(in);
        return 0;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int processBytes(byte[] in, int inOff, int inLen, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (in.length < inOff + inLen) {
            throw new DataLengthException("Input buffer too short");
        }
        this.data.write(in, inOff, inLen);
        return 0;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int doFinal(byte[] out, int outOff) throws IllegalStateException, InvalidCipherTextException {
        int len = processPacket(this.data.getBuffer(), 0, this.data.size(), out, outOff);
        reset();
        return len;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void reset() {
        this.cipher.reset();
        this.associatedText.reset();
        this.data.reset();
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public byte[] getMac() {
        byte[] mac = new byte[this.macSize];
        System.arraycopy(this.macBlock, 0, mac, 0, mac.length);
        return mac;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int getUpdateOutputSize(int len) {
        return 0;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int getOutputSize(int len) {
        int totalData = len + this.data.size();
        if (this.forEncryption) {
            return this.macSize + totalData;
        }
        if (totalData < this.macSize) {
            return 0;
        }
        return totalData - this.macSize;
    }

    public byte[] processPacket(byte[] in, int inOff, int inLen) throws IllegalStateException, InvalidCipherTextException {
        byte[] output;
        if (this.forEncryption) {
            output = new byte[(this.macSize + inLen)];
        } else if (inLen < this.macSize) {
            throw new InvalidCipherTextException("data too short");
        } else {
            output = new byte[(inLen - this.macSize)];
        }
        processPacket(in, inOff, inLen, output, 0);
        return output;
    }

    public int processPacket(byte[] in, int inOff, int inLen, byte[] output, int outOff) throws IllegalStateException, InvalidCipherTextException, DataLengthException {
        int outputLen;
        if (this.keyParam == null) {
            throw new IllegalStateException("CCM cipher unitialized.");
        }
        int q = 15 - this.nonce.length;
        if (q >= 4 || inLen < (1 << (q * 8))) {
            byte[] iv = new byte[this.blockSize];
            iv[0] = (byte) ((q - 1) & 7);
            System.arraycopy(this.nonce, 0, iv, 1, this.nonce.length);
            BlockCipher ctrCipher = new SICBlockCipher(this.cipher);
            ctrCipher.init(this.forEncryption, new ParametersWithIV(this.keyParam, iv));
            int inIndex = inOff;
            int outIndex = outOff;
            if (this.forEncryption) {
                outputLen = inLen + this.macSize;
                if (output.length < outputLen + outOff) {
                    throw new OutputLengthException("Output buffer too short.");
                }
                calculateMac(in, inOff, inLen, this.macBlock);
                byte[] encMac = new byte[this.blockSize];
                ctrCipher.processBlock(this.macBlock, 0, encMac, 0);
                while (inIndex < (inOff + inLen) - this.blockSize) {
                    ctrCipher.processBlock(in, inIndex, output, outIndex);
                    outIndex += this.blockSize;
                    inIndex += this.blockSize;
                }
                byte[] block = new byte[this.blockSize];
                System.arraycopy(in, inIndex, block, 0, (inLen + inOff) - inIndex);
                ctrCipher.processBlock(block, 0, block, 0);
                System.arraycopy(block, 0, output, outIndex, (inLen + inOff) - inIndex);
                System.arraycopy(encMac, 0, output, outOff + inLen, this.macSize);
            } else if (inLen < this.macSize) {
                throw new InvalidCipherTextException("data too short");
            } else {
                outputLen = inLen - this.macSize;
                if (output.length < outputLen + outOff) {
                    throw new OutputLengthException("Output buffer too short.");
                }
                System.arraycopy(in, inOff + outputLen, this.macBlock, 0, this.macSize);
                ctrCipher.processBlock(this.macBlock, 0, this.macBlock, 0);
                for (int i = this.macSize; i != this.macBlock.length; i++) {
                    this.macBlock[i] = 0;
                }
                while (inIndex < (inOff + outputLen) - this.blockSize) {
                    ctrCipher.processBlock(in, inIndex, output, outIndex);
                    outIndex += this.blockSize;
                    inIndex += this.blockSize;
                }
                byte[] block2 = new byte[this.blockSize];
                System.arraycopy(in, inIndex, block2, 0, outputLen - (inIndex - inOff));
                ctrCipher.processBlock(block2, 0, block2, 0);
                System.arraycopy(block2, 0, output, outIndex, outputLen - (inIndex - inOff));
                byte[] calculatedMacBlock = new byte[this.blockSize];
                calculateMac(output, outOff, outputLen, calculatedMacBlock);
                if (!Arrays.constantTimeAreEqual(this.macBlock, calculatedMacBlock)) {
                    throw new InvalidCipherTextException("mac check in CCM failed");
                }
            }
            return outputLen;
        }
        throw new IllegalStateException("CCM packet too large for choice of q.");
    }

    private int calculateMac(byte[] data2, int dataOff, int dataLen, byte[] macBlock2) {
        int extra;
        Mac cMac = new CBCBlockCipherMac(this.cipher, this.macSize * 8);
        cMac.init(this.keyParam);
        byte[] b0 = new byte[16];
        if (hasAssociatedText()) {
            b0[0] = (byte) (b0[0] | 64);
        }
        b0[0] = (byte) (b0[0] | ((((cMac.getMacSize() - 2) / 2) & 7) << 3));
        b0[0] = (byte) (b0[0] | (((15 - this.nonce.length) - 1) & 7));
        System.arraycopy(this.nonce, 0, b0, 1, this.nonce.length);
        int q = dataLen;
        int count = 1;
        while (q > 0) {
            b0[b0.length - count] = (byte) (q & GF2Field.MASK);
            q >>>= 8;
            count++;
        }
        cMac.update(b0, 0, b0.length);
        if (hasAssociatedText()) {
            int textLength = getAssociatedTextLength();
            if (textLength < 65280) {
                cMac.update((byte) (textLength >> 8));
                cMac.update((byte) textLength);
                extra = 2;
            } else {
                cMac.update((byte) -1);
                cMac.update((byte) -2);
                cMac.update((byte) (textLength >> 24));
                cMac.update((byte) (textLength >> 16));
                cMac.update((byte) (textLength >> 8));
                cMac.update((byte) textLength);
                extra = 6;
            }
            if (this.initialAssociatedText != null) {
                cMac.update(this.initialAssociatedText, 0, this.initialAssociatedText.length);
            }
            if (this.associatedText.size() > 0) {
                cMac.update(this.associatedText.getBuffer(), 0, this.associatedText.size());
            }
            int extra2 = (extra + textLength) % 16;
            if (extra2 != 0) {
                for (int i = extra2; i != 16; i++) {
                    cMac.update((byte) 0);
                }
            }
        }
        cMac.update(data2, dataOff, dataLen);
        return cMac.doFinal(macBlock2, 0);
    }

    private int getMacSize(boolean forEncryption2, int requestedMacBits) {
        if (!forEncryption2 || (requestedMacBits >= 32 && requestedMacBits <= 128 && (requestedMacBits & 15) == 0)) {
            return requestedMacBits >>> 3;
        }
        throw new IllegalArgumentException("tag length in octets must be one of {4,6,8,10,12,14,16}");
    }

    private int getAssociatedTextLength() {
        return (this.initialAssociatedText == null ? 0 : this.initialAssociatedText.length) + this.associatedText.size();
    }

    private boolean hasAssociatedText() {
        return getAssociatedTextLength() > 0;
    }

    /* access modifiers changed from: private */
    public class ExposedByteArrayOutputStream extends ByteArrayOutputStream {
        public ExposedByteArrayOutputStream() {
        }

        public byte[] getBuffer() {
            return this.buf;
        }
    }
}
