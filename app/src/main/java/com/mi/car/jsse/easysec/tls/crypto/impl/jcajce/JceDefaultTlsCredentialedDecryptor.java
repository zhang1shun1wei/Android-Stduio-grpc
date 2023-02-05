package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.Certificate;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.TlsCredentialedDecryptor;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsImplUtils;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import javax.crypto.Cipher;

public class JceDefaultTlsCredentialedDecryptor implements TlsCredentialedDecryptor {
    protected Certificate certificate;
    protected JcaTlsCrypto crypto;
    protected PrivateKey privateKey;

    public JceDefaultTlsCredentialedDecryptor(JcaTlsCrypto crypto2, Certificate certificate2, PrivateKey privateKey2) {
        if (crypto2 == null) {
            throw new IllegalArgumentException("'crypto' cannot be null");
        } else if (certificate2 == null) {
            throw new IllegalArgumentException("'certificate' cannot be null");
        } else if (certificate2.isEmpty()) {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        } else if (privateKey2 == null) {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        } else if ((privateKey2 instanceof RSAPrivateKey) || "RSA".equals(privateKey2.getAlgorithm())) {
            this.crypto = crypto2;
            this.certificate = certificate2;
            this.privateKey = privateKey2;
        } else {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey2.getClass().getName());
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsCredentials
    public Certificate getCertificate() {
        return this.certificate;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsCredentialedDecryptor
    public TlsSecret decrypt(TlsCryptoParameters cryptoParams, byte[] ciphertext) throws IOException {
        return safeDecryptPreMasterSecret(cryptoParams, this.privateKey, ciphertext);
    }

    /* access modifiers changed from: protected */
    public TlsSecret safeDecryptPreMasterSecret(TlsCryptoParameters cryptoParams, PrivateKey rsaServerPrivateKey, byte[] encryptedPreMasterSecret) {
        SecureRandom secureRandom = this.crypto.getSecureRandom();
        ProtocolVersion expectedVersion = cryptoParams.getRSAPreMasterSecretVersion();
        byte[] fallback = new byte[48];
        secureRandom.nextBytes(fallback);
        byte[] M = Arrays.clone(fallback);
        try {
            Cipher c = this.crypto.createRSAEncryptionCipher();
            c.init(2, rsaServerPrivateKey, secureRandom);
            byte[] m = c.doFinal(encryptedPreMasterSecret);
            if (m != null && m.length == 48) {
                M = m;
            }
        } catch (Exception e) {
        }
        if (0 == 0 || TlsImplUtils.isTLSv11(expectedVersion)) {
            int mask = (((expectedVersion.getMajorVersion() ^ (M[0] & 255)) | (expectedVersion.getMinorVersion() ^ (M[1] & 255))) - 1) >> 31;
            for (int i = 0; i < 48; i++) {
                M[i] = (byte) ((M[i] & mask) | (fallback[i] & (mask ^ -1)));
            }
        }
        return this.crypto.createSecret(M);
    }
}
