package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.AEADParameters;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayOutputStream;

public class KCCMBlockCipher implements AEADBlockCipher {
    private static final int BITS_IN_BYTE = 8;
    private static final int BYTES_IN_INT = 4;
    private static final int MAX_MAC_BIT_LENGTH = 512;
    private static final int MIN_MAC_BIT_LENGTH = 64;
    private byte[] G1;
    private int Nb_;
    private ExposedByteArrayOutputStream associatedText;
    private byte[] buffer;
    private byte[] counter;
    private ExposedByteArrayOutputStream data;
    private BlockCipher engine;
    private boolean forEncryption;
    private byte[] initialAssociatedText;
    private byte[] mac;
    private byte[] macBlock;
    private int macSize;
    private byte[] nonce;
    private byte[] s;

    private void setNb(int Nb) {
        if (Nb == 4 || Nb == 6 || Nb == 8) {
            this.Nb_ = Nb;
            return;
        }
        throw new IllegalArgumentException("Nb = 4 is recommended by DSTU7624 but can be changed to only 6 or 8 in this implementation");
    }

    public KCCMBlockCipher(BlockCipher engine2) {
        this(engine2, 4);
    }

    public KCCMBlockCipher(BlockCipher engine2, int nB) {
        this.associatedText = new ExposedByteArrayOutputStream();
        this.data = new ExposedByteArrayOutputStream();
        this.Nb_ = 4;
        this.engine = engine2;
        this.macSize = engine2.getBlockSize();
        this.nonce = new byte[engine2.getBlockSize()];
        this.initialAssociatedText = new byte[engine2.getBlockSize()];
        this.mac = new byte[engine2.getBlockSize()];
        this.macBlock = new byte[engine2.getBlockSize()];
        this.G1 = new byte[engine2.getBlockSize()];
        this.buffer = new byte[engine2.getBlockSize()];
        this.s = new byte[engine2.getBlockSize()];
        this.counter = new byte[engine2.getBlockSize()];
        setNb(nB);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void init(boolean forEncryption2, CipherParameters params) throws IllegalArgumentException {
        CipherParameters cipherParameters;
        if (params instanceof AEADParameters) {
            AEADParameters parameters = (AEADParameters) params;
            if (parameters.getMacSize() > 512 || parameters.getMacSize() < 64 || parameters.getMacSize() % 8 != 0) {
                throw new IllegalArgumentException("Invalid mac size specified");
            }
            this.nonce = parameters.getNonce();
            this.macSize = parameters.getMacSize() / 8;
            this.initialAssociatedText = parameters.getAssociatedText();
            cipherParameters = parameters.getKey();
        } else if (params instanceof ParametersWithIV) {
            this.nonce = ((ParametersWithIV) params).getIV();
            this.macSize = this.engine.getBlockSize();
            this.initialAssociatedText = null;
            cipherParameters = ((ParametersWithIV) params).getParameters();
        } else {
            throw new IllegalArgumentException("Invalid parameters specified");
        }
        this.mac = new byte[this.macSize];
        this.forEncryption = forEncryption2;
        this.engine.init(true, cipherParameters);
        this.counter[0] = 1;
        if (this.initialAssociatedText != null) {
            processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public String getAlgorithmName() {
        return this.engine.getAlgorithmName() + "/KCCM";
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher
    public BlockCipher getUnderlyingCipher() {
        return this.engine;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void processAADByte(byte in) {
        this.associatedText.write(in);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void processAADBytes(byte[] in, int inOff, int len) {
        this.associatedText.write(in, inOff, len);
    }

    private void processAAD(byte[] assocText, int assocOff, int assocLen, int dataLen) {
        if (assocLen - assocOff < this.engine.getBlockSize()) {
            throw new IllegalArgumentException("authText buffer too short");
        } else if (assocLen % this.engine.getBlockSize() != 0) {
            throw new IllegalArgumentException("padding not supported");
        } else {
            System.arraycopy(this.nonce, 0, this.G1, 0, (this.nonce.length - this.Nb_) - 1);
            intToBytes(dataLen, this.buffer, 0);
            System.arraycopy(this.buffer, 0, this.G1, (this.nonce.length - this.Nb_) - 1, 4);
            this.G1[this.G1.length - 1] = getFlag(true, this.macSize);
            this.engine.processBlock(this.G1, 0, this.macBlock, 0);
            intToBytes(assocLen, this.buffer, 0);
            if (assocLen <= this.engine.getBlockSize() - this.Nb_) {
                for (int byteIndex = 0; byteIndex < assocLen; byteIndex++) {
                    byte[] bArr = this.buffer;
                    int i = this.Nb_ + byteIndex;
                    bArr[i] = (byte) (bArr[i] ^ assocText[assocOff + byteIndex]);
                }
                for (int byteIndex2 = 0; byteIndex2 < this.engine.getBlockSize(); byteIndex2++) {
                    byte[] bArr2 = this.macBlock;
                    bArr2[byteIndex2] = (byte) (bArr2[byteIndex2] ^ this.buffer[byteIndex2]);
                }
                this.engine.processBlock(this.macBlock, 0, this.macBlock, 0);
                return;
            }
            for (int byteIndex3 = 0; byteIndex3 < this.engine.getBlockSize(); byteIndex3++) {
                byte[] bArr3 = this.macBlock;
                bArr3[byteIndex3] = (byte) (bArr3[byteIndex3] ^ this.buffer[byteIndex3]);
            }
            this.engine.processBlock(this.macBlock, 0, this.macBlock, 0);
            int authLen = assocLen;
            while (authLen != 0) {
                for (int byteIndex4 = 0; byteIndex4 < this.engine.getBlockSize(); byteIndex4++) {
                    byte[] bArr4 = this.macBlock;
                    bArr4[byteIndex4] = (byte) (bArr4[byteIndex4] ^ assocText[byteIndex4 + assocOff]);
                }
                this.engine.processBlock(this.macBlock, 0, this.macBlock, 0);
                assocOff += this.engine.getBlockSize();
                authLen -= this.engine.getBlockSize();
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int processByte(byte in, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        this.data.write(in);
        return 0;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int processBytes(byte[] in, int inOff, int inLen, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (in.length < inOff + inLen) {
            throw new DataLengthException("input buffer too short");
        }
        this.data.write(in, inOff, inLen);
        return 0;
    }

    public int processPacket(byte[] in, int inOff, int len, byte[] out, int outOff) throws IllegalStateException, InvalidCipherTextException {
        if (in.length - inOff < len) {
            throw new DataLengthException("input buffer too short");
        } else if (out.length - outOff < len) {
            throw new OutputLengthException("output buffer too short");
        } else {
            if (this.associatedText.size() > 0) {
                if (this.forEncryption) {
                    processAAD(this.associatedText.getBuffer(), 0, this.associatedText.size(), this.data.size());
                } else {
                    processAAD(this.associatedText.getBuffer(), 0, this.associatedText.size(), this.data.size() - this.macSize);
                }
            }
            if (this.forEncryption) {
                if (len % this.engine.getBlockSize() != 0) {
                    throw new DataLengthException("partial blocks not supported");
                }
                CalculateMac(in, inOff, len);
                this.engine.processBlock(this.nonce, 0, this.s, 0);
                int totalLength = len;
                while (totalLength > 0) {
                    ProcessBlock(in, inOff, len, out, outOff);
                    totalLength -= this.engine.getBlockSize();
                    inOff += this.engine.getBlockSize();
                    outOff += this.engine.getBlockSize();
                }
                for (int byteIndex = 0; byteIndex < this.counter.length; byteIndex++) {
                    byte[] bArr = this.s;
                    bArr[byteIndex] = (byte) (bArr[byteIndex] + this.counter[byteIndex]);
                }
                this.engine.processBlock(this.s, 0, this.buffer, 0);
                for (int byteIndex2 = 0; byteIndex2 < this.macSize; byteIndex2++) {
                    out[outOff + byteIndex2] = (byte) (this.buffer[byteIndex2] ^ this.macBlock[byteIndex2]);
                }
                System.arraycopy(this.macBlock, 0, this.mac, 0, this.macSize);
                reset();
                return this.macSize + len;
            } else if ((len - this.macSize) % this.engine.getBlockSize() != 0) {
                throw new DataLengthException("partial blocks not supported");
            } else {
                this.engine.processBlock(this.nonce, 0, this.s, 0);
                int blocks = len / this.engine.getBlockSize();
                for (int blockNum = 0; blockNum < blocks; blockNum++) {
                    ProcessBlock(in, inOff, len, out, outOff);
                    inOff += this.engine.getBlockSize();
                    outOff += this.engine.getBlockSize();
                }
                if (len > inOff) {
                    for (int byteIndex3 = 0; byteIndex3 < this.counter.length; byteIndex3++) {
                        byte[] bArr2 = this.s;
                        bArr2[byteIndex3] = (byte) (bArr2[byteIndex3] + this.counter[byteIndex3]);
                    }
                    this.engine.processBlock(this.s, 0, this.buffer, 0);
                    for (int byteIndex4 = 0; byteIndex4 < this.macSize; byteIndex4++) {
                        out[outOff + byteIndex4] = (byte) (this.buffer[byteIndex4] ^ in[inOff + byteIndex4]);
                    }
                    outOff += this.macSize;
                }
                for (int byteIndex5 = 0; byteIndex5 < this.counter.length; byteIndex5++) {
                    byte[] bArr3 = this.s;
                    bArr3[byteIndex5] = (byte) (bArr3[byteIndex5] + this.counter[byteIndex5]);
                }
                this.engine.processBlock(this.s, 0, this.buffer, 0);
                System.arraycopy(out, outOff - this.macSize, this.buffer, 0, this.macSize);
                CalculateMac(out, 0, outOff - this.macSize);
                System.arraycopy(this.macBlock, 0, this.mac, 0, this.macSize);
                byte[] calculatedMac = new byte[this.macSize];
                System.arraycopy(this.buffer, 0, calculatedMac, 0, this.macSize);
                if (!Arrays.constantTimeAreEqual(this.mac, calculatedMac)) {
                    throw new InvalidCipherTextException("mac check failed");
                }
                reset();
                return len - this.macSize;
            }
        }
    }

    private void ProcessBlock(byte[] input, int inOff, int len, byte[] output, int outOff) {
        for (int byteIndex = 0; byteIndex < this.counter.length; byteIndex++) {
            byte[] bArr = this.s;
            bArr[byteIndex] = (byte) (bArr[byteIndex] + this.counter[byteIndex]);
        }
        this.engine.processBlock(this.s, 0, this.buffer, 0);
        for (int byteIndex2 = 0; byteIndex2 < this.engine.getBlockSize(); byteIndex2++) {
            output[outOff + byteIndex2] = (byte) (this.buffer[byteIndex2] ^ input[inOff + byteIndex2]);
        }
    }

    private void CalculateMac(byte[] authText, int authOff, int len) {
        int totalLen = len;
        while (totalLen > 0) {
            for (int byteIndex = 0; byteIndex < this.engine.getBlockSize(); byteIndex++) {
                byte[] bArr = this.macBlock;
                bArr[byteIndex] = (byte) (bArr[byteIndex] ^ authText[authOff + byteIndex]);
            }
            this.engine.processBlock(this.macBlock, 0, this.macBlock, 0);
            totalLen -= this.engine.getBlockSize();
            authOff += this.engine.getBlockSize();
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int doFinal(byte[] out, int outOff) throws IllegalStateException, InvalidCipherTextException {
        int len = processPacket(this.data.getBuffer(), 0, this.data.size(), out, outOff);
        reset();
        return len;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public byte[] getMac() {
        return Arrays.clone(this.mac);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int getUpdateOutputSize(int len) {
        return len;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int getOutputSize(int len) {
        return this.macSize + len;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void reset() {
        Arrays.fill(this.G1, (byte) 0);
        Arrays.fill(this.buffer, (byte) 0);
        Arrays.fill(this.counter, (byte) 0);
        Arrays.fill(this.macBlock, (byte) 0);
        this.counter[0] = 1;
        this.data.reset();
        this.associatedText.reset();
        if (this.initialAssociatedText != null) {
            processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
        }
    }

    private void intToBytes(int num, byte[] outBytes, int outOff) {
        outBytes[outOff + 3] = (byte) (num >> 24);
        outBytes[outOff + 2] = (byte) (num >> 16);
        outBytes[outOff + 1] = (byte) (num >> 8);
        outBytes[outOff] = (byte) num;
    }

    private byte getFlag(boolean authTextPresents, int macSize2) {
        StringBuffer flagByte = new StringBuffer();
        if (authTextPresents) {
            flagByte.append("1");
        } else {
            flagByte.append("0");
        }
        switch (macSize2) {
            case 8:
                flagByte.append("010");
                break;
            case 16:
                flagByte.append("011");
                break;
            case 32:
                flagByte.append("100");
                break;
            case 48:
                flagByte.append("101");
                break;
            case 64:
                flagByte.append("110");
                break;
        }
        String binaryNb = Integer.toBinaryString(this.Nb_ - 1);
        while (binaryNb.length() < 4) {
            binaryNb = new StringBuffer(binaryNb).insert(0, "0").toString();
        }
        flagByte.append(binaryNb);
        return (byte) Integer.parseInt(flagByte.toString(), 2);
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
