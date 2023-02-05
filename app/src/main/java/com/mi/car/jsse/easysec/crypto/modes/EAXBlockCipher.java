package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.macs.CMac;
import com.mi.car.jsse.easysec.crypto.params.AEADParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;

public class EAXBlockCipher implements AEADBlockCipher {
    private static final byte cTAG = 2;
    private static final byte hTAG = 1;
    private static final byte nTAG = 0;
    private byte[] associatedTextMac = new byte[this.mac.getMacSize()];
    private int blockSize;
    private byte[] bufBlock;
    private int bufOff;
    private SICBlockCipher cipher;
    private boolean cipherInitialized;
    private boolean forEncryption;
    private byte[] initialAssociatedText;
    private Mac mac;
    private byte[] macBlock = new byte[this.blockSize];
    private int macSize;
    private byte[] nonceMac = new byte[this.mac.getMacSize()];

    public EAXBlockCipher(BlockCipher cipher2) {
        this.blockSize = cipher2.getBlockSize();
        this.mac = new CMac(cipher2);
        this.cipher = new SICBlockCipher(cipher2);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public String getAlgorithmName() {
        return this.cipher.getUnderlyingCipher().getAlgorithmName() + "/EAX";
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher
    public BlockCipher getUnderlyingCipher() {
        return this.cipher.getUnderlyingCipher();
    }

    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void init(boolean forEncryption2, CipherParameters params) throws IllegalArgumentException {
        byte[] nonce;
        CipherParameters keyParam;
        this.forEncryption = forEncryption2;
        if (params instanceof AEADParameters) {
            AEADParameters param = (AEADParameters) params;
            nonce = param.getNonce();
            this.initialAssociatedText = param.getAssociatedText();
            this.macSize = param.getMacSize() / 8;
            keyParam = param.getKey();
        } else if (params instanceof ParametersWithIV) {
            ParametersWithIV param2 = (ParametersWithIV) params;
            nonce = param2.getIV();
            this.initialAssociatedText = null;
            this.macSize = this.mac.getMacSize() / 2;
            keyParam = param2.getParameters();
        } else {
            throw new IllegalArgumentException("invalid parameters passed to EAX");
        }
        this.bufBlock = new byte[(forEncryption2 ? this.blockSize : this.blockSize + this.macSize)];
        byte[] tag = new byte[this.blockSize];
        this.mac.init(keyParam);
        tag[this.blockSize - 1] = 0;
        this.mac.update(tag, 0, this.blockSize);
        this.mac.update(nonce, 0, nonce.length);
        this.mac.doFinal(this.nonceMac, 0);
        this.cipher.init(true, new ParametersWithIV(keyParam, this.nonceMac));
        reset();
    }

    private void initCipher() {
        if (!this.cipherInitialized) {
            this.cipherInitialized = true;
            this.mac.doFinal(this.associatedTextMac, 0);
            byte[] tag = new byte[this.blockSize];
            tag[this.blockSize - 1] = cTAG;
            this.mac.update(tag, 0, this.blockSize);
        }
    }

    private void calculateMac() {
        byte[] outC = new byte[this.blockSize];
        this.mac.doFinal(outC, 0);
        for (int i = 0; i < this.macBlock.length; i++) {
            this.macBlock[i] = (byte) ((this.nonceMac[i] ^ this.associatedTextMac[i]) ^ outC[i]);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void reset() {
        reset(true);
    }

    private void reset(boolean clearMac) {
        this.cipher.reset();
        this.mac.reset();
        this.bufOff = 0;
        Arrays.fill(this.bufBlock, (byte) 0);
        if (clearMac) {
            Arrays.fill(this.macBlock, (byte) 0);
        }
        byte[] tag = new byte[this.blockSize];
        tag[this.blockSize - 1] = hTAG;
        this.mac.update(tag, 0, this.blockSize);
        this.cipherInitialized = false;
        if (this.initialAssociatedText != null) {
            processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void processAADByte(byte in) {
        if (this.cipherInitialized) {
            throw new IllegalStateException("AAD data cannot be added after encryption/decryption processing has begun.");
        }
        this.mac.update(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void processAADBytes(byte[] in, int inOff, int len) {
        if (this.cipherInitialized) {
            throw new IllegalStateException("AAD data cannot be added after encryption/decryption processing has begun.");
        }
        this.mac.update(in, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int processByte(byte in, byte[] out, int outOff) throws DataLengthException {
        initCipher();
        return process(in, out, outOff);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
        initCipher();
        if (in.length < inOff + len) {
            throw new DataLengthException("Input buffer too short");
        }
        int resultLen = 0;
        for (int i = 0; i != len; i++) {
            resultLen += process(in[inOff + i], out, outOff + resultLen);
        }
        return resultLen;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int doFinal(byte[] out, int outOff) throws IllegalStateException, InvalidCipherTextException {
        initCipher();
        int extra = this.bufOff;
        byte[] tmp = new byte[this.bufBlock.length];
        this.bufOff = 0;
        if (this.forEncryption) {
            if (out.length < outOff + extra + this.macSize) {
                throw new OutputLengthException("Output buffer too short");
            }
            this.cipher.processBlock(this.bufBlock, 0, tmp, 0);
            System.arraycopy(tmp, 0, out, outOff, extra);
            this.mac.update(tmp, 0, extra);
            calculateMac();
            System.arraycopy(this.macBlock, 0, out, outOff + extra, this.macSize);
            reset(false);
            return this.macSize + extra;
        } else if (extra < this.macSize) {
            throw new InvalidCipherTextException("data too short");
        } else if (out.length < (outOff + extra) - this.macSize) {
            throw new OutputLengthException("Output buffer too short");
        } else {
            if (extra > this.macSize) {
                this.mac.update(this.bufBlock, 0, extra - this.macSize);
                this.cipher.processBlock(this.bufBlock, 0, tmp, 0);
                System.arraycopy(tmp, 0, out, outOff, extra - this.macSize);
            }
            calculateMac();
            if (!verifyMac(this.bufBlock, extra - this.macSize)) {
                throw new InvalidCipherTextException("mac check in EAX failed");
            }
            reset(false);
            return extra - this.macSize;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public byte[] getMac() {
        byte[] mac2 = new byte[this.macSize];
        System.arraycopy(this.macBlock, 0, mac2, 0, this.macSize);
        return mac2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int getUpdateOutputSize(int len) {
        int totalData = len + this.bufOff;
        if (!this.forEncryption) {
            if (totalData < this.macSize) {
                return 0;
            }
            totalData -= this.macSize;
        }
        return totalData - (totalData % this.blockSize);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int getOutputSize(int len) {
        int totalData = len + this.bufOff;
        if (this.forEncryption) {
            return this.macSize + totalData;
        }
        if (totalData < this.macSize) {
            return 0;
        }
        return totalData - this.macSize;
    }

    private int process(byte b, byte[] out, int outOff) {
        int size;
        byte[] bArr = this.bufBlock;
        int i = this.bufOff;
        this.bufOff = i + 1;
        bArr[i] = b;
        if (this.bufOff != this.bufBlock.length) {
            return 0;
        }
        if (out.length < this.blockSize + outOff) {
            throw new OutputLengthException("Output buffer is too short");
        }
        if (this.forEncryption) {
            size = this.cipher.processBlock(this.bufBlock, 0, out, outOff);
            this.mac.update(out, outOff, this.blockSize);
        } else {
            this.mac.update(this.bufBlock, 0, this.blockSize);
            size = this.cipher.processBlock(this.bufBlock, 0, out, outOff);
        }
        this.bufOff = 0;
        if (this.forEncryption) {
            return size;
        }
        System.arraycopy(this.bufBlock, this.blockSize, this.bufBlock, 0, this.macSize);
        this.bufOff = this.macSize;
        return size;
    }

    private boolean verifyMac(byte[] mac2, int off) {
        int nonEqual = 0;
        for (int i = 0; i < this.macSize; i++) {
            nonEqual |= this.macBlock[i] ^ mac2[off + i];
        }
        return nonEqual == 0;
    }
}
