package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.X509ObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.util.DigestFactory;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2KeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceFujisakiCipher;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.util.AsymmetricHybridCipher;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;

public class McElieceFujisakiCipherSpi extends AsymmetricHybridCipher implements PKCSObjectIdentifiers, X509ObjectIdentifiers {
    private ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private McElieceFujisakiCipher cipher;
    private Digest digest;

    protected McElieceFujisakiCipherSpi(Digest digest2, McElieceFujisakiCipher cipher2) {
        this.digest = digest2;
        this.cipher = cipher2;
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt, com.mi.car.jsse.easysec.pqc.jcajce.provider.util.AsymmetricHybridCipher
    public byte[] update(byte[] input, int inOff, int inLen) {
        this.buf.write(input, inOff, inLen);
        return new byte[0];
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt, com.mi.car.jsse.easysec.pqc.jcajce.provider.util.AsymmetricHybridCipher
    public byte[] doFinal(byte[] input, int inOff, int inLen) throws BadPaddingException {
        update(input, inOff, inLen);
        byte[] data = this.buf.toByteArray();
        this.buf.reset();
        if (this.opMode == 1) {
            return this.cipher.messageEncrypt(data);
        }
        if (this.opMode == 2) {
            try {
                return this.cipher.messageDecrypt(data);
            } catch (InvalidCipherTextException e) {
                throw new BadPaddingException(e.getMessage());
            }
        } else {
            throw new IllegalStateException("unknown mode in doFinal");
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.AsymmetricHybridCipher
    public int encryptOutputSize(int inLen) {
        return 0;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.AsymmetricHybridCipher
    public int decryptOutputSize(int inLen) {
        return 0;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.AsymmetricHybridCipher
    public void initCipherEncrypt(Key key, AlgorithmParameterSpec params, SecureRandom sr) throws InvalidKeyException, InvalidAlgorithmParameterException {
        CipherParameters param = new ParametersWithRandom(McElieceCCA2KeysToParams.generatePublicKeyParameter((PublicKey) key), sr);
        this.digest.reset();
        this.cipher.init(true, param);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.AsymmetricHybridCipher
    public void initCipherDecrypt(Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        CipherParameters param = McElieceCCA2KeysToParams.generatePrivateKeyParameter((PrivateKey) key);
        this.digest.reset();
        this.cipher.init(false, param);
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public String getName() {
        return "McElieceFujisakiCipher";
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public int getKeySize(Key key) throws InvalidKeyException {
        McElieceCCA2KeyParameters mcElieceCCA2KeyParameters;
        if (key instanceof PublicKey) {
            mcElieceCCA2KeyParameters = (McElieceCCA2KeyParameters) McElieceCCA2KeysToParams.generatePublicKeyParameter((PublicKey) key);
        } else {
            mcElieceCCA2KeyParameters = (McElieceCCA2KeyParameters) McElieceCCA2KeysToParams.generatePrivateKeyParameter((PrivateKey) key);
        }
        return this.cipher.getKeySize(mcElieceCCA2KeyParameters);
    }

    public static class McElieceFujisaki extends McElieceFujisakiCipherSpi {
        public McElieceFujisaki() {
            super(DigestFactory.createSHA1(), new McElieceFujisakiCipher());
        }
    }
}
