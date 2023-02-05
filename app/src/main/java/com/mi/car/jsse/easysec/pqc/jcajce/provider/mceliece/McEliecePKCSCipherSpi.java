package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.X509ObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCipher;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.util.AsymmetricBlockCipher;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class McEliecePKCSCipherSpi extends AsymmetricBlockCipher implements PKCSObjectIdentifiers, X509ObjectIdentifiers {
    private McElieceCipher cipher;

    public McEliecePKCSCipherSpi(McElieceCipher cipher2) {
        this.cipher = cipher2;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.AsymmetricBlockCipher
    public void initCipherEncrypt(Key key, AlgorithmParameterSpec params, SecureRandom sr) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.cipher.init(true, new ParametersWithRandom(McElieceKeysToParams.generatePublicKeyParameter((PublicKey) key), sr));
        this.maxPlainTextSize = this.cipher.maxPlainTextSize;
        this.cipherTextSize = this.cipher.cipherTextSize;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.AsymmetricBlockCipher
    public void initCipherDecrypt(Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.cipher.init(false, McElieceKeysToParams.generatePrivateKeyParameter((PrivateKey) key));
        this.maxPlainTextSize = this.cipher.maxPlainTextSize;
        this.cipherTextSize = this.cipher.cipherTextSize;
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.AsymmetricBlockCipher
    public byte[] messageEncrypt(byte[] input) throws IllegalBlockSizeException, BadPaddingException {
        try {
            return this.cipher.messageEncrypt(input);
        } catch (Exception e) {
            throw new IllegalBlockSizeException(e.getMessage());
        }
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.AsymmetricBlockCipher
    public byte[] messageDecrypt(byte[] input) throws IllegalBlockSizeException, BadPaddingException {
        try {
            return this.cipher.messageDecrypt(input);
        } catch (Exception e) {
            throw new IllegalBlockSizeException(e.getMessage());
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public String getName() {
        return "McEliecePKCS";
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public int getKeySize(Key key) throws InvalidKeyException {
        McElieceKeyParameters mcElieceKeyParameters;
        if (key instanceof PublicKey) {
            mcElieceKeyParameters = (McElieceKeyParameters) McElieceKeysToParams.generatePublicKeyParameter((PublicKey) key);
        } else {
            mcElieceKeyParameters = (McElieceKeyParameters) McElieceKeysToParams.generatePrivateKeyParameter((PrivateKey) key);
        }
        return this.cipher.getKeySize(mcElieceKeyParameters);
    }

    public static class McEliecePKCS extends McEliecePKCSCipherSpi {
        public McEliecePKCS() {
            super(new McElieceCipher());
        }
    }
}
