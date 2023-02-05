package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.jce.interfaces.ECPublicKey;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import com.mi.car.jsse.easysec.tls.NamedGroup;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoException;
import com.mi.car.jsse.easysec.tls.crypto.TlsECConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsECDomain;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;

public class JceTlsECDomain implements TlsECDomain {
    protected final JcaTlsCrypto crypto;
    protected final TlsECConfig ecConfig;
    protected final ECCurve ecCurve;
    protected final ECParameterSpec ecSpec;

    public JceTlsECDomain(JcaTlsCrypto crypto2, TlsECConfig ecConfig2) {
        ECParameterSpec spec;
        int namedGroup = ecConfig2.getNamedGroup();
        if (!NamedGroup.refersToAnECDSACurve(namedGroup) || (spec = ECUtil.getECParameterSpec(crypto2, NamedGroup.getCurveName(namedGroup))) == null) {
            throw new IllegalArgumentException("NamedGroup not supported: " + NamedGroup.getText(namedGroup));
        }
        this.crypto = crypto2;
        this.ecConfig = ecConfig2;
        this.ecSpec = spec;
        this.ecCurve = ECUtil.convertCurve(spec.getCurve(), spec.getOrder(), spec.getCofactor());
    }

    public JceTlsSecret calculateECDHAgreement(PrivateKey privateKey, PublicKey publicKey) throws IOException {
        try {
            return this.crypto.adoptLocalSecret(this.crypto.calculateKeyAgreement("ECDH", privateKey, publicKey, "TlsPremasterSecret"));
        } catch (GeneralSecurityException e) {
            throw new TlsCryptoException("cannot calculate secret", e);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsECDomain
    public TlsAgreement createECDH() {
        return new JceTlsECDH(this);
    }

    public ECPoint decodePoint(byte[] encoding) throws IOException {
        return this.ecCurve.decodePoint(encoding);
    }

    public PublicKey decodePublicKey(byte[] encoding) throws IOException {
        try {
            ECPoint point = decodePoint(encoding).normalize();
            return this.crypto.getHelper().createKeyFactory("EC").generatePublic(new ECPublicKeySpec(new java.security.spec.ECPoint(point.getAffineXCoord().toBigInteger(), point.getAffineYCoord().toBigInteger()), this.ecSpec));
        } catch (Exception e) {
            throw new TlsFatalAlert((short) 47, (Throwable) e);
        }
    }

    public byte[] encodePoint(ECPoint point) throws IOException {
        return point.getEncoded(false);
    }

    public byte[] encodePublicKey(PublicKey publicKey) throws IOException {
        if (publicKey instanceof ECPublicKey) {
            return encodePoint(((ECPublicKey) publicKey).getQ());
        }
        if (!(publicKey instanceof java.security.interfaces.ECPublicKey)) {
            return SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getPublicKeyData().getOctets();
        }
        java.security.spec.ECPoint w = ((java.security.interfaces.ECPublicKey) publicKey).getW();
        return encodePoint(this.ecCurve.createPoint(w.getAffineX(), w.getAffineY()));
    }

    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = this.crypto.getHelper().createKeyPairGenerator("EC");
            keyPairGenerator.initialize(this.ecSpec, this.crypto.getSecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }
}
