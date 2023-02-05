package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.modes.kgcm.KGCMMultiplier;
import com.mi.car.jsse.easysec.crypto.modes.kgcm.Tables16kKGCMMultiplier_512;
import com.mi.car.jsse.easysec.crypto.modes.kgcm.Tables4kKGCMMultiplier_128;
import com.mi.car.jsse.easysec.crypto.modes.kgcm.Tables8kKGCMMultiplier_256;
import com.mi.car.jsse.easysec.crypto.params.AEADParameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.ByteArrayOutputStream;

public class KGCMBlockCipher implements AEADBlockCipher {
    private static final int MIN_MAC_BITS = 64;
    private ExposedByteArrayOutputStream associatedText = new ExposedByteArrayOutputStream();
    private long[] b;
    private final int blockSize;
    private BufferedBlockCipher ctrEngine;
    private ExposedByteArrayOutputStream data = new ExposedByteArrayOutputStream();
    private BlockCipher engine;
    private boolean forEncryption;
    private byte[] initialAssociatedText;
    private byte[] iv;
    private byte[] macBlock;
    private int macSize;
    private KGCMMultiplier multiplier;

    private static KGCMMultiplier createDefaultMultiplier(int blockSize2) {
        switch (blockSize2) {
            case 16:
                return new Tables4kKGCMMultiplier_128();
            case 32:
                return new Tables8kKGCMMultiplier_256();
            case 64:
                return new Tables16kKGCMMultiplier_512();
            default:
                throw new IllegalArgumentException("Only 128, 256, and 512 -bit block sizes supported");
        }
    }

    public KGCMBlockCipher(BlockCipher dstu7624Engine) {
        this.engine = dstu7624Engine;
        this.ctrEngine = new BufferedBlockCipher(new KCTRBlockCipher(this.engine));
        this.macSize = -1;
        this.blockSize = this.engine.getBlockSize();
        this.initialAssociatedText = new byte[this.blockSize];
        this.iv = new byte[this.blockSize];
        this.multiplier = createDefaultMultiplier(this.blockSize);
        this.b = new long[(this.blockSize >>> 3)];
        this.macBlock = null;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void init(boolean forEncryption2, CipherParameters params) throws IllegalArgumentException {
        KeyParameter engineParam;
        this.forEncryption = forEncryption2;
        if (params instanceof AEADParameters) {
            AEADParameters param = (AEADParameters) params;
            byte[] iv2 = param.getNonce();
            int diff = this.iv.length - iv2.length;
            Arrays.fill(this.iv, (byte) 0);
            System.arraycopy(iv2, 0, this.iv, diff, iv2.length);
            this.initialAssociatedText = param.getAssociatedText();
            int macSizeBits = param.getMacSize();
            if (macSizeBits < 64 || macSizeBits > (this.blockSize << 3) || (macSizeBits & 7) != 0) {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }
            this.macSize = macSizeBits >>> 3;
            engineParam = param.getKey();
            if (this.initialAssociatedText != null) {
                processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
            }
        } else if (params instanceof ParametersWithIV) {
            ParametersWithIV param2 = (ParametersWithIV) params;
            byte[] iv3 = param2.getIV();
            int diff2 = this.iv.length - iv3.length;
            Arrays.fill(this.iv, (byte) 0);
            System.arraycopy(iv3, 0, this.iv, diff2, iv3.length);
            this.initialAssociatedText = null;
            this.macSize = this.blockSize;
            engineParam = (KeyParameter) param2.getParameters();
        } else {
            throw new IllegalArgumentException("Invalid parameter passed");
        }
        this.macBlock = new byte[this.blockSize];
        this.ctrEngine.init(true, new ParametersWithIV(engineParam, this.iv));
        this.engine.init(true, engineParam);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public String getAlgorithmName() {
        return this.engine.getAlgorithmName() + "/KGCM";
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

    private void processAAD(byte[] authText, int authOff, int len) {
        int pos = authOff;
        int end = authOff + len;
        while (pos < end) {
            xorWithInput(this.b, authText, pos);
            this.multiplier.multiplyH(this.b);
            pos += this.blockSize;
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

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int doFinal(byte[] out, int outOff) throws IllegalStateException, InvalidCipherTextException {
        int resultLen;
        int len = this.data.size();
        if (this.forEncryption || len >= this.macSize) {
            byte[] temp = new byte[this.blockSize];
            this.engine.processBlock(temp, 0, temp, 0);
            long[] H = new long[(this.blockSize >>> 3)];
            Pack.littleEndianToLong(temp, 0, H);
            this.multiplier.init(H);
            Arrays.fill(temp, (byte) 0);
            Arrays.fill(H, 0);
            int lenAAD = this.associatedText.size();
            if (lenAAD > 0) {
                processAAD(this.associatedText.getBuffer(), 0, lenAAD);
            }
            if (!this.forEncryption) {
                int ctLen = len - this.macSize;
                if (out.length - outOff < ctLen) {
                    throw new OutputLengthException("Output buffer too short");
                }
                calculateMac(this.data.getBuffer(), 0, ctLen, lenAAD);
                int resultLen2 = this.ctrEngine.processBytes(this.data.getBuffer(), 0, ctLen, out, outOff);
                resultLen = resultLen2 + this.ctrEngine.doFinal(out, outOff + resultLen2);
            } else if ((out.length - outOff) - this.macSize < len) {
                throw new OutputLengthException("Output buffer too short");
            } else {
                int resultLen3 = this.ctrEngine.processBytes(this.data.getBuffer(), 0, len, out, outOff);
                resultLen = resultLen3 + this.ctrEngine.doFinal(out, outOff + resultLen3);
                calculateMac(out, outOff, len, lenAAD);
            }
            if (this.macBlock == null) {
                throw new IllegalStateException("mac is not calculated");
            } else if (this.forEncryption) {
                System.arraycopy(this.macBlock, 0, out, outOff + resultLen, this.macSize);
                reset();
                return resultLen + this.macSize;
            } else {
                byte[] mac = new byte[this.macSize];
                System.arraycopy(this.data.getBuffer(), len - this.macSize, mac, 0, this.macSize);
                byte[] calculatedMac = new byte[this.macSize];
                System.arraycopy(this.macBlock, 0, calculatedMac, 0, this.macSize);
                if (!Arrays.constantTimeAreEqual(mac, calculatedMac)) {
                    throw new InvalidCipherTextException("mac verification failed");
                }
                reset();
                return resultLen;
            }
        } else {
            throw new InvalidCipherTextException("data too short");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public byte[] getMac() {
        byte[] mac = new byte[this.macSize];
        System.arraycopy(this.macBlock, 0, mac, 0, this.macSize);
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

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void reset() {
        Arrays.fill(this.b, 0);
        this.engine.reset();
        this.data.reset();
        this.associatedText.reset();
        if (this.initialAssociatedText != null) {
            processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
        }
    }

    private void calculateMac(byte[] input, int inOff, int len, int lenAAD) {
        int pos = inOff;
        int end = inOff + len;
        while (pos < end) {
            xorWithInput(this.b, input, pos);
            this.multiplier.multiplyH(this.b);
            pos += this.blockSize;
        }
        long[] jArr = this.b;
        jArr[0] = jArr[0] ^ ((((long) lenAAD) & 4294967295L) << 3);
        long[] jArr2 = this.b;
        int i = this.blockSize >>> 4;
        jArr2[i] = jArr2[i] ^ ((((long) len) & 4294967295L) << 3);
        this.macBlock = Pack.longToLittleEndian(this.b);
        this.engine.processBlock(this.macBlock, 0, this.macBlock, 0);
    }

    private static void xorWithInput(long[] z, byte[] buf, int off) {
        for (int i = 0; i < z.length; i++) {
            z[i] = z[i] ^ Pack.littleEndianToLong(buf, off);
            off += 8;
        }
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
