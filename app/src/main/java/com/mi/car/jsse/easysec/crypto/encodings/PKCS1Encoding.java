package com.mi.car.jsse.easysec.crypto.encodings;

import com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Properties;
import java.security.SecureRandom;

public class PKCS1Encoding implements AsymmetricBlockCipher {
    private static final int HEADER_LENGTH = 10;
    public static final String NOT_STRICT_LENGTH_ENABLED_PROPERTY = "com.mi.car.jsse.easysec.pkcs1.not_strict";
    public static final String STRICT_LENGTH_ENABLED_PROPERTY = "com.mi.car.jsse.easysec.pkcs1.strict";
    private byte[] blockBuffer;
    private AsymmetricBlockCipher engine;
    private byte[] fallback = null;
    private boolean forEncryption;
    private boolean forPrivateKey;
    private int pLen = -1;
    private SecureRandom random;
    private boolean useStrictLength;

    public PKCS1Encoding(AsymmetricBlockCipher cipher) {
        this.engine = cipher;
        this.useStrictLength = useStrict();
    }

    public PKCS1Encoding(AsymmetricBlockCipher cipher, int pLen2) {
        this.engine = cipher;
        this.useStrictLength = useStrict();
        this.pLen = pLen2;
    }

    public PKCS1Encoding(AsymmetricBlockCipher cipher, byte[] fallback2) {
        this.engine = cipher;
        this.useStrictLength = useStrict();
        this.fallback = fallback2;
        this.pLen = fallback2.length;
    }

    private boolean useStrict() {
        boolean z = true;
        if (Properties.isOverrideSetTo(NOT_STRICT_LENGTH_ENABLED_PROPERTY, true)) {
            return false;
        }
        if (Properties.isOverrideSetTo(STRICT_LENGTH_ENABLED_PROPERTY, false)) {
            z = false;
        }
        return z;
    }

    public AsymmetricBlockCipher getUnderlyingCipher() {
        return this.engine;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public void init(boolean forEncryption2, CipherParameters param) {
        AsymmetricKeyParameter kParam;
        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.random = rParam.getRandom();
            kParam = (AsymmetricKeyParameter) rParam.getParameters();
        } else {
            kParam = (AsymmetricKeyParameter) param;
            if (!kParam.isPrivate() && forEncryption2) {
                this.random = CryptoServicesRegistrar.getSecureRandom();
            }
        }
        this.engine.init(forEncryption2, param);
        this.forPrivateKey = kParam.isPrivate();
        this.forEncryption = forEncryption2;
        this.blockBuffer = new byte[this.engine.getOutputBlockSize()];
        if (this.pLen > 0 && this.fallback == null && this.random == null) {
            throw new IllegalArgumentException("encoder requires random");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getInputBlockSize() {
        int baseBlockSize = this.engine.getInputBlockSize();
        if (this.forEncryption) {
            return baseBlockSize - 10;
        }
        return baseBlockSize;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public int getOutputBlockSize() {
        int baseBlockSize = this.engine.getOutputBlockSize();
        return this.forEncryption ? baseBlockSize : baseBlockSize - 10;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricBlockCipher
    public byte[] processBlock(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        if (this.forEncryption) {
            return encodeBlock(in, inOff, inLen);
        }
        return decodeBlock(in, inOff, inLen);
    }

    private byte[] encodeBlock(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        if (inLen > getInputBlockSize()) {
            throw new IllegalArgumentException("input data too large");
        }
        byte[] block = new byte[this.engine.getInputBlockSize()];
        if (this.forPrivateKey) {
            block[0] = 1;
            for (int i = 1; i != (block.length - inLen) - 1; i++) {
                block[i] = -1;
            }
        } else {
            this.random.nextBytes(block);
            block[0] = 2;
            for (int i2 = 1; i2 != (block.length - inLen) - 1; i2++) {
                while (block[i2] == 0) {
                    block[i2] = (byte) this.random.nextInt();
                }
            }
        }
        block[(block.length - inLen) - 1] = 0;
        System.arraycopy(in, inOff, block, block.length - inLen, inLen);
        return this.engine.processBlock(block, 0, block.length);
    }

    private static int checkPkcs1Encoding(byte[] encoded, int pLen2) {
        int correct = 0 | (encoded[0] ^ 2);
        int plen = encoded.length - (pLen2 + 1);
        for (int i = 1; i < plen; i++) {
            byte b = encoded[i];
            int tmp = b | (b >> 1);
            int tmp2 = tmp | (tmp >> 2);
            correct |= ((tmp2 | (tmp2 >> 4)) & 1) - 1;
        }
        int correct2 = correct | encoded[encoded.length - (pLen2 + 1)];
        int correct3 = correct2 | (correct2 >> 1);
        int correct4 = correct3 | (correct3 >> 2);
        return (((correct4 | (correct4 >> 4)) & 1) - 1) ^ -1;
    }

    private byte[] decodeBlockOrRandom(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        byte[] random2;
        boolean z;
        byte[] data;
        if (!this.forPrivateKey) {
            throw new InvalidCipherTextException("sorry, this method is only for decryption, not for signing");
        }
        byte[] block = this.engine.processBlock(in, inOff, inLen);
        if (this.fallback == null) {
            random2 = new byte[this.pLen];
            this.random.nextBytes(random2);
        } else {
            random2 = this.fallback;
        }
        boolean z2 = this.useStrictLength;
        if ((block.length != this.engine.getOutputBlockSize()) && z2) {
            data = this.blockBuffer;
        } else {
            data = block;
        }
        int correct = checkPkcs1Encoding(data, this.pLen);
        byte[] result = new byte[this.pLen];
        for (int i = 0; i < this.pLen; i++) {
            result[i] = (byte) ((data[(data.length - this.pLen) + i] & (correct ^ -1)) | (random2[i] & correct));
        }
        Arrays.fill(data, (byte) 0);
        return result;
    }

    private byte[] decodeBlock(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        boolean z;
        byte[] data;
        boolean badType;
        boolean z2 = true;
        if (this.pLen != -1) {
            return decodeBlockOrRandom(in, inOff, inLen);
        }
        byte[] block = this.engine.processBlock(in, inOff, inLen);
        boolean z3 = this.useStrictLength;
        if (block.length != this.engine.getOutputBlockSize()) {
            z = true;
        } else {
            z = false;
        }
        boolean incorrectLength = z3 & z;
        if (block.length < getOutputBlockSize()) {
            data = this.blockBuffer;
        } else {
            data = block;
        }
        byte type = data[0];
        if (this.forPrivateKey) {
            badType = type != 2;
        } else {
            badType = type != 1;
        }
        int start = findStart(type, data) + 1;
        if (start >= 10) {
            z2 = false;
        }
        if (badType || z2) {
            Arrays.fill(data, (byte) 0);
            throw new InvalidCipherTextException("block incorrect");
        } else if (incorrectLength) {
            Arrays.fill(data, (byte) 0);
            throw new InvalidCipherTextException("block incorrect size");
        } else {
            byte[] result = new byte[(data.length - start)];
            System.arraycopy(data, start, result, 0, result.length);
            return result;
        }
    }

    private int findStart(byte type, byte[] block) throws InvalidCipherTextException {
        boolean z;
        int start = -1;
        boolean padErr = false;
        for (int i = 1; i != block.length; i++) {
            byte pad = block[i];
            if ((start < 0) && (pad == 0)) {
                start = i;
            }
            boolean z2 = (type == 1) & (start < 0);
            padErr |= (pad != -1) & z2;
        }
        if (padErr) {
            return -1;
        }
        return start;
    }
}
