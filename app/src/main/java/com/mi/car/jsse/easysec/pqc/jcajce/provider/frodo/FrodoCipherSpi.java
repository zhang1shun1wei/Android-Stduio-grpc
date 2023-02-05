package com.mi.car.jsse.easysec.pqc.jcajce.provider.frodo;

import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.SecretWithEncapsulation;
import com.mi.car.jsse.easysec.crypto.Wrapper;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.jcajce.spec.KEMParameterSpec;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoKEMExtractor;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoKEMGenerator;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.util.WrapUtil;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Exceptions;
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
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

class FrodoCipherSpi extends CipherSpi {
    private final String algorithmName;
    private AlgorithmParameters engineParams;
    private FrodoKEMGenerator kemGen;
    private KEMParameterSpec kemParameterSpec;
    private SecureRandom random;
    private BCFrodoPrivateKey unwrapKey;
    private BCFrodoPublicKey wrapKey;

    FrodoCipherSpi(String algorithmName2) throws NoSuchAlgorithmException {
        this.algorithmName = algorithmName2;
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("Cannot support mode " + mode);
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new NoSuchPaddingException("Padding " + padding + " unknown");
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public int engineGetKeySize(Key key) {
        return 2048;
    }

    /* access modifiers changed from: protected */
    public int engineGetBlockSize() {
        return 0;
    }

    /* access modifiers changed from: protected */
    public int engineGetOutputSize(int i) {
        return -1;
    }

    /* access modifiers changed from: protected */
    public byte[] engineGetIV() {
        return null;
    }

    /* access modifiers changed from: protected */
    public AlgorithmParameters engineGetParameters() {
        if (this.engineParams == null) {
            try {
                this.engineParams = AlgorithmParameters.getInstance(this.algorithmName, "BCPQC");
                this.engineParams.init(this.kemParameterSpec);
            } catch (Exception e) {
                throw Exceptions.illegalStateException(e.toString(), e);
            }
        }
        return this.engineParams;
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public void engineInit(int opmode, Key key, SecureRandom random2) throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random2);
        } catch (InvalidAlgorithmParameterException e) {
            throw Exceptions.illegalArgumentException(e.getMessage(), e);
        }
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public void engineInit(int opmode, Key key, AlgorithmParameterSpec paramSpec, SecureRandom random2) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (random2 == null) {
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }
        if (paramSpec == null) {
            this.kemParameterSpec = new KEMParameterSpec("AES-KWP");
        } else if (!(paramSpec instanceof KEMParameterSpec)) {
            throw new InvalidAlgorithmParameterException(this.algorithmName + " can only accept KTSParameterSpec");
        } else {
            this.kemParameterSpec = (KEMParameterSpec) paramSpec;
        }
        if (opmode == 3) {
            if (key instanceof BCFrodoPublicKey) {
                this.wrapKey = (BCFrodoPublicKey) key;
                this.kemGen = new FrodoKEMGenerator(random2);
                return;
            }
            throw new InvalidKeyException("Only an RSA public key can be used for wrapping");
        } else if (opmode != 4) {
            throw new InvalidParameterException("Cipher only valid for wrapping/unwrapping");
        } else if (key instanceof BCFrodoPrivateKey) {
            this.unwrapKey = (BCFrodoPrivateKey) key;
        } else {
            throw new InvalidKeyException("Only an RSA private key can be used for unwrapping");
        }
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public void engineInit(int opmode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec paramSpec = null;
        if (algorithmParameters != null) {
            try {
                paramSpec = algorithmParameters.getParameterSpec(KEMParameterSpec.class);
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + algorithmParameters.toString());
            }
        }
        engineInit(opmode, key, paramSpec, this.random);
    }

    /* access modifiers changed from: protected */
    public byte[] engineUpdate(byte[] bytes, int i, int i1) {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public int engineUpdate(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public byte[] engineDoFinal(byte[] bytes, int i, int i1) throws IllegalBlockSizeException, BadPaddingException {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public int engineDoFinal(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        if (key.getEncoded() == null) {
            throw new InvalidKeyException("Cannot wrap key, null encoding.");
        }
        try {
            SecretWithEncapsulation secEnc = this.kemGen.generateEncapsulated(this.wrapKey.getKeyParams());
            Wrapper kWrap = WrapUtil.getWrapper(this.kemParameterSpec.getKeyAlgorithmName());
            kWrap.init(true, new KeyParameter(secEnc.getSecret()));
            byte[] encapsulation = secEnc.getEncapsulation();
            secEnc.destroy();
            byte[] keyToWrap = key.getEncoded();
            byte[] rv = Arrays.concatenate(encapsulation, kWrap.wrap(keyToWrap, 0, keyToWrap.length));
            Arrays.clear(keyToWrap);
            return rv;
        } catch (IllegalArgumentException e) {
            throw new IllegalBlockSizeException("unable to generate KTS secret: " + e.getMessage());
        } catch (DestroyFailedException e2) {
            throw new IllegalBlockSizeException("unable to destroy interim values: " + e2.getMessage());
        }
    }

    /* access modifiers changed from: protected */
    @Override // javax.crypto.CipherSpi
    public Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) throws InvalidKeyException, NoSuchAlgorithmException {
        if (wrappedKeyType != 3) {
            throw new InvalidKeyException("only SECRET_KEY supported");
        }
        try {
            FrodoKEMExtractor kemExt = new FrodoKEMExtractor(this.unwrapKey.getKeyParams());
            byte[] secret = kemExt.extractSecret(Arrays.copyOfRange(wrappedKey, 0, kemExt.getInputSize()));
            Wrapper kWrap = WrapUtil.getWrapper(this.kemParameterSpec.getKeyAlgorithmName());
            KeyParameter keyParameter = new KeyParameter(secret);
            Arrays.clear(secret);
            kWrap.init(false, keyParameter);
            byte[] keyEncBytes = Arrays.copyOfRange(wrappedKey, kemExt.getInputSize(), wrappedKey.length);
            SecretKey rv = new SecretKeySpec(kWrap.unwrap(keyEncBytes, 0, keyEncBytes.length), wrappedKeyAlgorithm);
            Arrays.clear(keyParameter.getKey());
            return rv;
        } catch (IllegalArgumentException e) {
            throw new NoSuchAlgorithmException("unable to extract KTS secret: " + e.getMessage());
        } catch (InvalidCipherTextException e2) {
            throw new InvalidKeyException("unable to extract KTS secret: " + e2.getMessage());
        }
    }

    public static class Base extends FrodoCipherSpi {
        public Base() throws NoSuchAlgorithmException {
            super("Frodo");
        }
    }
}
