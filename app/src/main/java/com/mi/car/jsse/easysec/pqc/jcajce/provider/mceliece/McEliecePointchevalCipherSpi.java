package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.X509ObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.util.DigestFactory;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2KeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McEliecePointchevalCipher;
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

public class McEliecePointchevalCipherSpi extends AsymmetricHybridCipher implements PKCSObjectIdentifiers, X509ObjectIdentifiers {
    private ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private McEliecePointchevalCipher cipher;
    private Digest digest;

    protected McEliecePointchevalCipherSpi(Digest digest2, McEliecePointchevalCipher cipher2) {
        this.digest = digest2;
        this.cipher = cipher2;
        this.buf = new ByteArrayOutputStream();
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
        if (this.opMode != 2) {
            return null;
        }
        try {
            return this.cipher.messageDecrypt(data);
        } catch (InvalidCipherTextException e) {
            throw new BadPaddingException(e.getMessage());
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
        return "McEliecePointchevalCipher";
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

    public static class McEliecePointcheval extends McEliecePointchevalCipherSpi {
        public McEliecePointcheval() {
            super(DigestFactory.createSHA1(), new McEliecePointchevalCipher());
        }
    }

    public static class McEliecePointcheval224 extends McEliecePointchevalCipherSpi {
        public McEliecePointcheval224() {
            super(DigestFactory.createSHA224(), new McEliecePointchevalCipher());
        }
    }

    public static class McEliecePointcheval256 extends McEliecePointchevalCipherSpi {
        public McEliecePointcheval256() {
            super(DigestFactory.createSHA256(), new McEliecePointchevalCipher());
        }
    }

    public static class McEliecePointcheval384 extends McEliecePointchevalCipherSpi {
        public McEliecePointcheval384() {
            super(DigestFactory.createSHA384(), new McEliecePointchevalCipher());
        }
    }

    public static class McEliecePointcheval512 extends McEliecePointchevalCipherSpi {
        public McEliecePointcheval512() {
            super(DigestFactory.createSHA512(), new McEliecePointchevalCipher());
        }
    }
}
