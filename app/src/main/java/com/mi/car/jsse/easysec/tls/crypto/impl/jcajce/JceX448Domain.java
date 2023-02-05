package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.asn1.edec.EdECObjectIdentifiers;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoException;
import com.mi.car.jsse.easysec.tls.crypto.TlsECDomain;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class JceX448Domain implements TlsECDomain {
    protected final JcaTlsCrypto crypto;

    public JceX448Domain(JcaTlsCrypto crypto2) {
        this.crypto = crypto2;
    }

    public JceTlsSecret calculateECDHAgreement(PrivateKey privateKey, PublicKey publicKey) throws IOException {
        try {
            byte[] secret = this.crypto.calculateKeyAgreement("X448", privateKey, publicKey, "TlsPremasterSecret");
            if (secret == null || secret.length != 56) {
                throw new TlsCryptoException("invalid secret calculated");
            } else if (!Arrays.areAllZeroes(secret, 0, secret.length)) {
                return this.crypto.adoptLocalSecret(secret);
            } else {
                throw new TlsFatalAlert((short) 40);
            }
        } catch (GeneralSecurityException e) {
            throw new TlsCryptoException("cannot calculate secret", e);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsECDomain
    public TlsAgreement createECDH() {
        return new JceX448(this);
    }

    public PublicKey decodePublicKey(byte[] encoding) throws IOException {
        return XDHUtil.decodePublicKey(this.crypto, "X448", EdECObjectIdentifiers.id_X448, encoding);
    }

    public byte[] encodePublicKey(PublicKey publicKey) throws IOException {
        return XDHUtil.encodePublicKey(publicKey);
    }

    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = this.crypto.getHelper().createKeyPairGenerator("X448");
            keyPairGenerator.initialize(448, this.crypto.getSecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }
}
