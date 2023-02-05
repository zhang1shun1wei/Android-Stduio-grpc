package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsEncryptor;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

final class JcaTlsRSAEncryptor implements TlsEncryptor {
    private final JcaTlsCrypto crypto;
    private final PublicKey pubKeyRSA;

    JcaTlsRSAEncryptor(JcaTlsCrypto crypto2, PublicKey pubKeyRSA2) {
        this.crypto = crypto2;
        this.pubKeyRSA = pubKeyRSA2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsEncryptor
    public byte[] encrypt(byte[] input, int inOff, int length) throws IOException {
        try {
            Cipher c = this.crypto.createRSAEncryptionCipher();
            try {
                c.init(3, this.pubKeyRSA, this.crypto.getSecureRandom());
                return c.wrap(new SecretKeySpec(input, inOff, length, "TLS"));
            } catch (Exception e) {
                try {
                    c.init(1, this.pubKeyRSA, this.crypto.getSecureRandom());
                    return c.doFinal(input, inOff, length);
                } catch (Exception e2) {
                    throw new TlsFatalAlert((short) 80, (Throwable) e);
                }
            }
        } catch (GeneralSecurityException e3) {
            throw new TlsFatalAlert((short) 80, (Throwable) e3);
        }
    }
}
