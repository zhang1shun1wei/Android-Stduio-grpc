package com.mi.car.jsse.easysec.pqc.jcajce.provider.util;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public abstract class CipherSpiExt extends CipherSpi {
    public static final int DECRYPT_MODE = 2;
    public static final int ENCRYPT_MODE = 1;
    protected int opMode;

    public abstract int doFinal(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;

    public abstract byte[] doFinal(byte[] bArr, int i, int i2) throws IllegalBlockSizeException, BadPaddingException;

    public abstract int getBlockSize();

    public abstract byte[] getIV();

    public abstract int getKeySize(Key key) throws InvalidKeyException;

    public abstract String getName();

    public abstract int getOutputSize(int i);

    public abstract AlgorithmParameterSpec getParameters();

    public abstract void initDecrypt(Key key, AlgorithmParameterSpec algorithmParameterSpec) throws InvalidKeyException, InvalidAlgorithmParameterException;

    public abstract void initEncrypt(Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException;

    /* access modifiers changed from: protected */
    public abstract void setMode(String str) throws NoSuchAlgorithmException;

    /* access modifiers changed from: protected */
    public abstract void setPadding(String str) throws NoSuchPaddingException;

    public abstract int update(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws ShortBufferException;

    public abstract byte[] update(byte[] bArr, int i, int i2);

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public final void engineInit(int opMode2, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(opMode2, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public final void engineInit(int opMode2, Key key, AlgorithmParameters algParams, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (algParams == null) {
            engineInit(opMode2, key, random);
        } else {
            engineInit(opMode2, key, (AlgorithmParameterSpec) null, random);
        }
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public void engineInit(int opMode2, Key key, AlgorithmParameterSpec params, SecureRandom javaRand) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null && !(params instanceof AlgorithmParameterSpec)) {
            throw new InvalidAlgorithmParameterException();
        } else if (key == null || !(key instanceof Key)) {
            throw new InvalidKeyException();
        } else {
            this.opMode = opMode2;
            if (opMode2 == 1) {
                initEncrypt(key, params, javaRand);
            } else if (opMode2 == 2) {
                initDecrypt(key, params);
            }
        }
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public final byte[] engineDoFinal(byte[] input, int inOff, int inLen) throws IllegalBlockSizeException, BadPaddingException {
        return doFinal(input, inOff, inLen);
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public final int engineDoFinal(byte[] input, int inOff, int inLen, byte[] output, int outOff) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return doFinal(input, inOff, inLen, output, outOff);
    }

    /* access modifiers changed from: protected */
    public final int engineGetBlockSize() {
        return getBlockSize();
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public final int engineGetKeySize(Key key) throws InvalidKeyException {
        if (key instanceof Key) {
            return getKeySize(key);
        }
        throw new InvalidKeyException("Unsupported key.");
    }

    /* access modifiers changed from: protected */
    public final byte[] engineGetIV() {
        return getIV();
    }

    /* access modifiers changed from: protected */
    public final int engineGetOutputSize(int inLen) {
        return getOutputSize(inLen);
    }

    /* access modifiers changed from: protected */
    public final AlgorithmParameters engineGetParameters() {
        return null;
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public final void engineSetMode(String modeName) throws NoSuchAlgorithmException {
        setMode(modeName);
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public final void engineSetPadding(String paddingName) throws NoSuchPaddingException {
        setPadding(paddingName);
    }

    /* access modifiers changed from: protected */
    public final byte[] engineUpdate(byte[] input, int inOff, int inLen) {
        return update(input, inOff, inLen);
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public final int engineUpdate(byte[] input, int inOff, int inLen, byte[] output, int outOff) throws ShortBufferException {
        return update(input, inOff, inLen, output, outOff);
    }

    public final byte[] update(byte[] input) {
        return update(input, 0, input.length);
    }

    public final byte[] doFinal() throws IllegalBlockSizeException, BadPaddingException {
        return doFinal(null, 0, 0);
    }

    public final byte[] doFinal(byte[] input) throws IllegalBlockSizeException, BadPaddingException {
        return doFinal(input, 0, input.length);
    }
}
