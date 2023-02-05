package com.mi.car.jsse.easysec.pqc.jcajce.provider.mceliece;

import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.X509ObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.util.DigestFactory;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceCCA2KeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.mceliece.McElieceKobaraImaiCipher;
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

public class McElieceKobaraImaiCipherSpi extends AsymmetricHybridCipher implements PKCSObjectIdentifiers, X509ObjectIdentifiers {
    private ByteArrayOutputStream buf;
    private McElieceKobaraImaiCipher cipher;
    private Digest digest;

    public McElieceKobaraImaiCipherSpi() {
        this.buf = new ByteArrayOutputStream();
        this.buf = new ByteArrayOutputStream();
    }

    protected McElieceKobaraImaiCipherSpi(Digest digest2, McElieceKobaraImaiCipher cipher2) {
        this.buf = new ByteArrayOutputStream();
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
        if (this.opMode == 1) {
            return this.cipher.messageEncrypt(pad());
        }
        if (this.opMode == 2) {
            try {
                byte[] inputOfDecr = this.buf.toByteArray();
                this.buf.reset();
                return unpad(this.cipher.messageDecrypt(inputOfDecr));
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
        this.buf.reset();
        CipherParameters param = new ParametersWithRandom(McElieceCCA2KeysToParams.generatePublicKeyParameter((PublicKey) key), sr);
        this.digest.reset();
        this.cipher.init(true, param);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.AsymmetricHybridCipher
    public void initCipherDecrypt(Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.buf.reset();
        CipherParameters param = McElieceCCA2KeysToParams.generatePrivateKeyParameter((PrivateKey) key);
        this.digest.reset();
        this.cipher.init(false, param);
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public String getName() {
        return "McElieceKobaraImaiCipher";
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.provider.util.CipherSpiExt
    public int getKeySize(Key key) throws InvalidKeyException {
        if (key instanceof PublicKey) {
            return this.cipher.getKeySize((McElieceCCA2KeyParameters) McElieceCCA2KeysToParams.generatePublicKeyParameter((PublicKey) key));
        } else if (key instanceof PrivateKey) {
            return this.cipher.getKeySize((McElieceCCA2KeyParameters) McElieceCCA2KeysToParams.generatePrivateKeyParameter((PrivateKey) key));
        } else {
            throw new InvalidKeyException();
        }
    }

    private byte[] pad() {
        this.buf.write(1);
        byte[] result = this.buf.toByteArray();
        this.buf.reset();
        return result;
    }

    private byte[] unpad(byte[] pmBytes) throws BadPaddingException {
        int index = pmBytes.length - 1;
        while (index >= 0 && pmBytes[index] == 0) {
            index--;
        }
        if (pmBytes[index] != 1) {
            throw new BadPaddingException("invalid ciphertext");
        }
        byte[] mBytes = new byte[index];
        System.arraycopy(pmBytes, 0, mBytes, 0, index);
        return mBytes;
    }

    public static class McElieceKobaraImai extends McElieceKobaraImaiCipherSpi {
        public McElieceKobaraImai() {
            super(DigestFactory.createSHA1(), new McElieceKobaraImaiCipher());
        }
    }

    public static class McElieceKobaraImai224 extends McElieceKobaraImaiCipherSpi {
        public McElieceKobaraImai224() {
            super(DigestFactory.createSHA224(), new McElieceKobaraImaiCipher());
        }
    }

    public static class McElieceKobaraImai256 extends McElieceKobaraImaiCipherSpi {
        public McElieceKobaraImai256() {
            super(DigestFactory.createSHA256(), new McElieceKobaraImaiCipher());
        }
    }

    public static class McElieceKobaraImai384 extends McElieceKobaraImaiCipherSpi {
        public McElieceKobaraImai384() {
            super(DigestFactory.createSHA384(), new McElieceKobaraImaiCipher());
        }
    }

    public static class McElieceKobaraImai512 extends McElieceKobaraImaiCipherSpi {
        public McElieceKobaraImai512() {
            super(DigestFactory.createSHA512(), new McElieceKobaraImaiCipher());
        }
    }
}
