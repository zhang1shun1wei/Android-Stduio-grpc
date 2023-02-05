package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.AEADParameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;
import java.util.Vector;

public class OCBBlockCipher implements AEADBlockCipher {
    private static final int BLOCK_SIZE = 16;
    private byte[] Checksum;
    private byte[] KtopInput = null;
    private Vector L;
    private byte[] L_Asterisk;
    private byte[] L_Dollar;
    private byte[] OffsetHASH;
    private byte[] OffsetMAIN = new byte[16];
    private byte[] OffsetMAIN_0 = new byte[16];
    private byte[] Stretch = new byte[24];
    private byte[] Sum;
    private boolean forEncryption;
    private byte[] hashBlock;
    private long hashBlockCount;
    private int hashBlockPos;
    private BlockCipher hashCipher;
    private byte[] initialAssociatedText;
    private byte[] macBlock;
    private int macSize;
    private byte[] mainBlock;
    private long mainBlockCount;
    private int mainBlockPos;
    private BlockCipher mainCipher;

    public OCBBlockCipher(BlockCipher hashCipher2, BlockCipher mainCipher2) {
        if (hashCipher2 == null) {
            throw new IllegalArgumentException("'hashCipher' cannot be null");
        } else if (hashCipher2.getBlockSize() != 16) {
            throw new IllegalArgumentException("'hashCipher' must have a block size of 16");
        } else if (mainCipher2 == null) {
            throw new IllegalArgumentException("'mainCipher' cannot be null");
        } else if (mainCipher2.getBlockSize() != 16) {
            throw new IllegalArgumentException("'mainCipher' must have a block size of 16");
        } else if (!hashCipher2.getAlgorithmName().equals(mainCipher2.getAlgorithmName())) {
            throw new IllegalArgumentException("'hashCipher' and 'mainCipher' must be the same algorithm");
        } else {
            this.hashCipher = hashCipher2;
            this.mainCipher = mainCipher2;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher
    public BlockCipher getUnderlyingCipher() {
        return this.mainCipher;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public String getAlgorithmName() {
        return this.mainCipher.getAlgorithmName() + "/OCB";
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void init(boolean forEncryption2, CipherParameters parameters) throws IllegalArgumentException {
        byte[] N;
        KeyParameter keyParameter;
        int i;
        boolean oldForEncryption = this.forEncryption;
        this.forEncryption = forEncryption2;
        this.macBlock = null;
        if (parameters instanceof AEADParameters) {
            AEADParameters aeadParameters = (AEADParameters) parameters;
            N = aeadParameters.getNonce();
            this.initialAssociatedText = aeadParameters.getAssociatedText();
            int macSizeBits = aeadParameters.getMacSize();
            if (macSizeBits < 64 || macSizeBits > 128 || macSizeBits % 8 != 0) {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }
            this.macSize = macSizeBits / 8;
            keyParameter = aeadParameters.getKey();
        } else if (parameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) parameters;
            N = parametersWithIV.getIV();
            this.initialAssociatedText = null;
            this.macSize = 16;
            keyParameter = (KeyParameter) parametersWithIV.getParameters();
        } else {
            throw new IllegalArgumentException("invalid parameters passed to OCB");
        }
        this.hashBlock = new byte[16];
        if (forEncryption2) {
            i = 16;
        } else {
            i = this.macSize + 16;
        }
        this.mainBlock = new byte[i];
        if (N == null) {
            N = new byte[0];
        }
        if (N.length > 15) {
            throw new IllegalArgumentException("IV must be no more than 15 bytes");
        }
        if (keyParameter != null) {
            this.hashCipher.init(true, keyParameter);
            this.mainCipher.init(forEncryption2, keyParameter);
            this.KtopInput = null;
        } else if (oldForEncryption != forEncryption2) {
            throw new IllegalArgumentException("cannot change encrypting state without providing key.");
        }
        this.L_Asterisk = new byte[16];
        this.hashCipher.processBlock(this.L_Asterisk, 0, this.L_Asterisk, 0);
        this.L_Dollar = OCB_double(this.L_Asterisk);
        this.L = new Vector();
        this.L.addElement(OCB_double(this.L_Dollar));
        int bottom = processNonce(N);
        int bits = bottom % 8;
        int bytes = bottom / 8;
        if (bits == 0) {
            System.arraycopy(this.Stretch, bytes, this.OffsetMAIN_0, 0, 16);
        } else {
            for (int i2 = 0; i2 < 16; i2++) {
                int b1 = this.Stretch[bytes] & 255;
                bytes++;
                this.OffsetMAIN_0[i2] = (byte) ((b1 << bits) | ((this.Stretch[bytes] & 255) >>> (8 - bits)));
            }
        }
        this.hashBlockPos = 0;
        this.mainBlockPos = 0;
        this.hashBlockCount = 0;
        this.mainBlockCount = 0;
        this.OffsetHASH = new byte[16];
        this.Sum = new byte[16];
        System.arraycopy(this.OffsetMAIN_0, 0, this.OffsetMAIN, 0, 16);
        this.Checksum = new byte[16];
        if (this.initialAssociatedText != null) {
            processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
        }
    }

    /* access modifiers changed from: protected */
    public int processNonce(byte[] N) {
        byte[] nonce = new byte[16];
        System.arraycopy(N, 0, nonce, nonce.length - N.length, N.length);
        nonce[0] = (byte) (this.macSize << 4);
        int length = 15 - N.length;
        nonce[length] = (byte) (nonce[length] | 1);
        int bottom = nonce[15] & 63;
        nonce[15] = (byte) (nonce[15] & 192);
        if (this.KtopInput == null || !Arrays.areEqual(nonce, this.KtopInput)) {
            byte[] Ktop = new byte[16];
            this.KtopInput = nonce;
            this.hashCipher.processBlock(this.KtopInput, 0, Ktop, 0);
            System.arraycopy(Ktop, 0, this.Stretch, 0, 16);
            for (int i = 0; i < 8; i++) {
                this.Stretch[i + 16] = (byte) (Ktop[i] ^ Ktop[i + 1]);
            }
        }
        return bottom;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public byte[] getMac() {
        if (this.macBlock == null) {
            return new byte[this.macSize];
        }
        return Arrays.clone(this.macBlock);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int getOutputSize(int len) {
        int totalData = len + this.mainBlockPos;
        if (this.forEncryption) {
            return this.macSize + totalData;
        }
        if (totalData < this.macSize) {
            return 0;
        }
        return totalData - this.macSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int getUpdateOutputSize(int len) {
        int totalData = len + this.mainBlockPos;
        if (!this.forEncryption) {
            if (totalData < this.macSize) {
                return 0;
            }
            totalData -= this.macSize;
        }
        return totalData - (totalData % 16);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void processAADByte(byte input) {
        this.hashBlock[this.hashBlockPos] = input;
        int i = this.hashBlockPos + 1;
        this.hashBlockPos = i;
        if (i == this.hashBlock.length) {
            processHashBlock();
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void processAADBytes(byte[] input, int off, int len) {
        for (int i = 0; i < len; i++) {
            this.hashBlock[this.hashBlockPos] = input[off + i];
            int i2 = this.hashBlockPos + 1;
            this.hashBlockPos = i2;
            if (i2 == this.hashBlock.length) {
                processHashBlock();
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int processByte(byte input, byte[] output, int outOff) throws DataLengthException {
        this.mainBlock[this.mainBlockPos] = input;
        int i = this.mainBlockPos + 1;
        this.mainBlockPos = i;
        if (i != this.mainBlock.length) {
            return 0;
        }
        processMainBlock(output, outOff);
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff) throws DataLengthException {
        if (input.length < inOff + len) {
            throw new DataLengthException("Input buffer too short");
        }
        int resultLen = 0;
        for (int i = 0; i < len; i++) {
            this.mainBlock[this.mainBlockPos] = input[inOff + i];
            int i2 = this.mainBlockPos + 1;
            this.mainBlockPos = i2;
            if (i2 == this.mainBlock.length) {
                processMainBlock(output, outOff + resultLen);
                resultLen += 16;
            }
        }
        return resultLen;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int doFinal(byte[] output, int outOff) throws IllegalStateException, InvalidCipherTextException {
        byte[] tag = null;
        if (!this.forEncryption) {
            if (this.mainBlockPos < this.macSize) {
                throw new InvalidCipherTextException("data too short");
            }
            this.mainBlockPos -= this.macSize;
            tag = new byte[this.macSize];
            System.arraycopy(this.mainBlock, this.mainBlockPos, tag, 0, this.macSize);
        }
        if (this.hashBlockPos > 0) {
            OCB_extend(this.hashBlock, this.hashBlockPos);
            updateHASH(this.L_Asterisk);
        }
        if (this.mainBlockPos > 0) {
            if (this.forEncryption) {
                OCB_extend(this.mainBlock, this.mainBlockPos);
                xor(this.Checksum, this.mainBlock);
            }
            xor(this.OffsetMAIN, this.L_Asterisk);
            byte[] Pad = new byte[16];
            this.hashCipher.processBlock(this.OffsetMAIN, 0, Pad, 0);
            xor(this.mainBlock, Pad);
            if (output.length < this.mainBlockPos + outOff) {
                throw new OutputLengthException("Output buffer too short");
            }
            System.arraycopy(this.mainBlock, 0, output, outOff, this.mainBlockPos);
            if (!this.forEncryption) {
                OCB_extend(this.mainBlock, this.mainBlockPos);
                xor(this.Checksum, this.mainBlock);
            }
        }
        xor(this.Checksum, this.OffsetMAIN);
        xor(this.Checksum, this.L_Dollar);
        this.hashCipher.processBlock(this.Checksum, 0, this.Checksum, 0);
        xor(this.Checksum, this.Sum);
        this.macBlock = new byte[this.macSize];
        System.arraycopy(this.Checksum, 0, this.macBlock, 0, this.macSize);
        int resultLen = this.mainBlockPos;
        if (this.forEncryption) {
            if (output.length < outOff + resultLen + this.macSize) {
                throw new OutputLengthException("Output buffer too short");
            }
            System.arraycopy(this.macBlock, 0, output, outOff + resultLen, this.macSize);
            resultLen += this.macSize;
        } else if (!Arrays.constantTimeAreEqual(this.macBlock, tag)) {
            throw new InvalidCipherTextException("mac check in OCB failed");
        }
        reset(false);
        return resultLen;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void reset() {
        reset(true);
    }

    /* access modifiers changed from: protected */
    public void clear(byte[] bs) {
        if (bs != null) {
            Arrays.fill(bs, (byte) 0);
        }
    }

    /* access modifiers changed from: protected */
    public byte[] getLSub(int n) {
        while (n >= this.L.size()) {
            this.L.addElement(OCB_double((byte[]) this.L.lastElement()));
        }
        return (byte[]) this.L.elementAt(n);
    }

    /* access modifiers changed from: protected */
    public void processHashBlock() {
        long j = this.hashBlockCount + 1;
        this.hashBlockCount = j;
        updateHASH(getLSub(OCB_ntz(j)));
        this.hashBlockPos = 0;
    }

    /* access modifiers changed from: protected */
    public void processMainBlock(byte[] output, int outOff) {
        if (output.length < outOff + 16) {
            throw new OutputLengthException("Output buffer too short");
        }
        if (this.forEncryption) {
            xor(this.Checksum, this.mainBlock);
            this.mainBlockPos = 0;
        }
        byte[] bArr = this.OffsetMAIN;
        long j = this.mainBlockCount + 1;
        this.mainBlockCount = j;
        xor(bArr, getLSub(OCB_ntz(j)));
        xor(this.mainBlock, this.OffsetMAIN);
        this.mainCipher.processBlock(this.mainBlock, 0, this.mainBlock, 0);
        xor(this.mainBlock, this.OffsetMAIN);
        System.arraycopy(this.mainBlock, 0, output, outOff, 16);
        if (!this.forEncryption) {
            xor(this.Checksum, this.mainBlock);
            System.arraycopy(this.mainBlock, 16, this.mainBlock, 0, this.macSize);
            this.mainBlockPos = this.macSize;
        }
    }

    /* access modifiers changed from: protected */
    public void reset(boolean clearMac) {
        this.hashCipher.reset();
        this.mainCipher.reset();
        clear(this.hashBlock);
        clear(this.mainBlock);
        this.hashBlockPos = 0;
        this.mainBlockPos = 0;
        this.hashBlockCount = 0;
        this.mainBlockCount = 0;
        clear(this.OffsetHASH);
        clear(this.Sum);
        System.arraycopy(this.OffsetMAIN_0, 0, this.OffsetMAIN, 0, 16);
        clear(this.Checksum);
        if (clearMac) {
            this.macBlock = null;
        }
        if (this.initialAssociatedText != null) {
            processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
        }
    }

    /* access modifiers changed from: protected */
    public void updateHASH(byte[] LSub) {
        xor(this.OffsetHASH, LSub);
        xor(this.hashBlock, this.OffsetHASH);
        this.hashCipher.processBlock(this.hashBlock, 0, this.hashBlock, 0);
        xor(this.Sum, this.hashBlock);
    }

    protected static byte[] OCB_double(byte[] block) {
        byte[] result = new byte[16];
        result[15] = (byte) (result[15] ^ (135 >>> ((1 - shiftLeft(block, result)) << 3)));
        return result;
    }

    protected static void OCB_extend(byte[] block, int pos) {
        block[pos] = Byte.MIN_VALUE;
        while (true) {
            pos++;
            if (pos < 16) {
                block[pos] = 0;
            } else {
                return;
            }
        }
    }

    protected static int OCB_ntz(long x) {
        if (x == 0) {
            return 64;
        }
        int n = 0;
        while ((1 & x) == 0) {
            n++;
            x >>>= 1;
        }
        return n;
    }

    protected static int shiftLeft(byte[] block, byte[] output) {
        int i = 16;
        int bit = 0;
        while (true) {
            i--;
            if (i < 0) {
                return bit;
            }
            int b = block[i] & 255;
            output[i] = (byte) ((b << 1) | bit);
            bit = (b >>> 7) & 1;
        }
    }

    protected static void xor(byte[] block, byte[] val) {
        for (int i = 15; i >= 0; i--) {
            block[i] = (byte) (block[i] ^ val[i]);
        }
    }
}
