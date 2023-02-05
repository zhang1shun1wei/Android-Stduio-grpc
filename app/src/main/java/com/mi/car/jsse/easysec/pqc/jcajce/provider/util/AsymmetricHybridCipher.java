package com.mi.car.jsse.easysec.pqc.jcajce.provider.util;

import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;

public abstract class AsymmetricHybridCipher extends CipherSpiExt {
    protected AlgorithmParameterSpec paramSpec;

    /* access modifiers changed from: protected */
    public abstract int decryptOutputSize(int i);

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public abstract byte[] doFinal(byte[] bArr, int i, int i2) throws BadPaddingException;

    /* access modifiers changed from: protected */
    public abstract int encryptOutputSize(int i);

    /* access modifiers changed from: protected */
    public abstract void initCipherDecrypt(Key key, AlgorithmParameterSpec algorithmParameterSpec) throws InvalidKeyException, InvalidAlgorithmParameterException;

    /* access modifiers changed from: protected */
    public abstract void initCipherEncrypt(Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException;

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public abstract byte[] update(byte[] bArr, int i, int i2);

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public final void setMode(String modeName) {
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public final void setPadding(String paddingName) {
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public final byte[] getIV() {
        return null;
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public final int getBlockSize() {
        return 0;
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public final AlgorithmParameterSpec getParameters() {
        return this.paramSpec;
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public final int getOutputSize(int inLen) {
        if (this.opMode == 1) {
            return encryptOutputSize(inLen);
        }
        return decryptOutputSize(inLen);
    }

    public final void initEncrypt(Key key) throws InvalidKeyException {
        try {
            initEncrypt(key, null, CryptoServicesRegistrar.getSecureRandom());
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException("This cipher needs algorithm parameters for initialization (cannot be null).");
        }
    }

    public final void initEncrypt(Key key, SecureRandom random) throws InvalidKeyException {
        try {
            initEncrypt(key, null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException("This cipher needs algorithm parameters for initialization (cannot be null).");
        }
    }

    public final void initEncrypt(Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        initEncrypt(key, params, CryptoServicesRegistrar.getSecureRandom());
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public final void initEncrypt(Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.opMode = 1;
        initCipherEncrypt(key, params, random);
    }

    public final void initDecrypt(Key key) throws InvalidKeyException {
        try {
            initDecrypt(key, null);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException("This cipher needs algorithm parameters for initialization (cannot be null).");
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public final void initDecrypt(Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.opMode = 2;
        initCipherDecrypt(key, params);
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public final int update(byte[] input, int inOff, int inLen, byte[] output, int outOff) throws ShortBufferException {
        if (output.length < getOutputSize(inLen)) {
            throw new ShortBufferException("output");
        }
        byte[] out = update(input, inOff, inLen);
        System.arraycopy(out, 0, output, outOff, out.length);
        return out.length;
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public final int doFinal(byte[] input, int inOff, int inLen, byte[] output, int outOff) throws ShortBufferException, BadPaddingException {
        if (output.length < getOutputSize(inLen)) {
            throw new ShortBufferException("Output buffer too short.");
        }
        byte[] out = doFinal(input, inOff, inLen);
        System.arraycopy(out, 0, output, outOff, out.length);
        return out.length;
    }
}
