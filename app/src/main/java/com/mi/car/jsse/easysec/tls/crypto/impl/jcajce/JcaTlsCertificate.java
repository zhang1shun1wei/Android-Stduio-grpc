package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.Certificate;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoException;
import com.mi.car.jsse.easysec.tls.crypto.TlsEncryptor;
import com.mi.car.jsse.easysec.tls.crypto.TlsVerifier;
import com.mi.car.jsse.easysec.tls.crypto.impl.RSAUtil;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.interfaces.DHPublicKey;


public class JcaTlsCertificate implements TlsCertificate {
    protected static final int KU_DIGITAL_SIGNATURE = 0;
    protected static final int KU_NON_REPUDIATION = 1;
    protected static final int KU_KEY_ENCIPHERMENT = 2;
    protected static final int KU_DATA_ENCIPHERMENT = 3;
    protected static final int KU_KEY_AGREEMENT = 4;
    protected static final int KU_KEY_CERT_SIGN = 5;
    protected static final int KU_CRL_SIGN = 6;
    protected static final int KU_ENCIPHER_ONLY = 7;
    protected static final int KU_DECIPHER_ONLY = 8;
    protected final JcaTlsCrypto crypto;
    protected final X509Certificate certificate;
    protected DHPublicKey pubKeyDH;
    protected ECPublicKey pubKeyEC;
    protected PublicKey pubKeyRSA;

    public static JcaTlsCertificate convert(JcaTlsCrypto crypto, TlsCertificate certificate) throws IOException {
        return certificate instanceof JcaTlsCertificate ? (JcaTlsCertificate)certificate : new JcaTlsCertificate(crypto, certificate.getEncoded());
    }

    public static X509Certificate parseCertificate(JcaJceHelper helper, byte[] encoding) throws IOException {
        try {
            ASN1Primitive asn1 = TlsUtils.readASN1Object(encoding);
            byte[] derEncoding = Certificate.getInstance(asn1).getEncoded("DER");
            ByteArrayInputStream input = new ByteArrayInputStream(derEncoding);
            X509Certificate certificate = (X509Certificate)helper.createCertificateFactory("X.509").generateCertificate(input);
            if (input.available() != 0) {
                throw new IOException("Extra data detected in stream");
            } else {
                return certificate;
            }
        } catch (GeneralSecurityException var6) {
            throw new TlsCryptoException("unable to decode certificate", var6);
        }
    }

    public JcaTlsCertificate(JcaTlsCrypto crypto, byte[] encoding) throws IOException {
        this(crypto, parseCertificate(crypto.getHelper(), encoding));
    }

    public JcaTlsCertificate(JcaTlsCrypto crypto, X509Certificate certificate) {
        this.pubKeyDH = null;
        this.pubKeyEC = null;
        this.pubKeyRSA = null;
        this.crypto = crypto;
        this.certificate = certificate;
    }

    public TlsEncryptor createEncryptor(int tlsCertificateRole) throws IOException {
        this.validateKeyUsageBit(2);
        switch(tlsCertificateRole) {
            case 3:
                this.pubKeyRSA = this.getPubKeyRSA();
                return new JcaTlsRSAEncryptor(this.crypto, this.pubKeyRSA);
            default:
                throw new TlsFatalAlert((short)46);
        }
    }

    public TlsVerifier createVerifier(short signatureAlgorithm) throws IOException {
        switch(signatureAlgorithm) {
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
                return this.createVerifier(SignatureScheme.from((short)8, signatureAlgorithm));
            default:
                this.validateKeyUsageBit(0);
                switch(signatureAlgorithm) {
                    case 1:
                        this.validateRSA_PKCS1();
                        return new JcaTlsRSAVerifier(this.crypto, this.getPubKeyRSA());
                    case 2:
                        return new JcaTlsDSAVerifier(this.crypto, this.getPubKeyDSS());
                    case 3:
                        return new JcaTlsECDSAVerifier(this.crypto, this.getPubKeyEC());
                    default:
                        throw new TlsFatalAlert((short)46);
                }
        }
    }

    public TlsVerifier createVerifier(int signatureScheme) throws IOException {
        this.validateKeyUsageBit(0);
        switch(signatureScheme) {
            case 513:
            case 1025:
            case 1281:
            case 1537:
                this.validateRSA_PKCS1();
                return new JcaTlsRSAVerifier(this.crypto, this.getPubKeyRSA());
            case 515:
            case 1027:
            case 1283:
            case 1539:
            case 2074:
            case 2075:
            case 2076:
                return new JcaTlsECDSA13Verifier(this.crypto, this.getPubKeyEC(), signatureScheme);
            case 2052:
            case 2053:
            case 2054:
                this.validateRSA_PSS_RSAE();
                return new JcaTlsRSAPSSVerifier(this.crypto, this.getPubKeyRSA(), signatureScheme);
            case 2055:
                return new JcaTlsEd25519Verifier(this.crypto, this.getPubKeyEd25519());
            case 2056:
                return new JcaTlsEd448Verifier(this.crypto, this.getPubKeyEd448());
            case 2057:
            case 2058:
            case 2059:
                this.validateRSA_PSS_PSS(SignatureScheme.getSignatureAlgorithm(signatureScheme));
                return new JcaTlsRSAPSSVerifier(this.crypto, this.getPubKeyRSA(), signatureScheme);
            default:
                throw new TlsFatalAlert((short)46);
        }
    }

    public byte[] getEncoded() throws IOException {
        try {
            return this.certificate.getEncoded();
        } catch (CertificateEncodingException var2) {
            throw new TlsCryptoException("unable to encode certificate: " + var2.getMessage(), var2);
        }
    }

    public byte[] getExtension(ASN1ObjectIdentifier extensionOID) throws IOException {
        byte[] encoding = this.certificate.getExtensionValue(extensionOID.getId());
        return encoding == null ? null : ((ASN1OctetString)ASN1Primitive.fromByteArray(encoding)).getOctets();
    }

    public BigInteger getSerialNumber() {
        return this.certificate.getSerialNumber();
    }

    public String getSigAlgOID() {
        return this.certificate.getSigAlgOID();
    }

    public ASN1Encodable getSigAlgParams() throws IOException {
        byte[] derEncoding = this.certificate.getSigAlgParams();
        if (null == derEncoding) {
            return null;
        } else {
            ASN1Primitive asn1 = TlsUtils.readASN1Object(derEncoding);
            TlsUtils.requireDEREncoding(asn1, derEncoding);
            return asn1;
        }
    }

    DHPublicKey getPubKeyDH() throws IOException {
        try {
            return (DHPublicKey)this.getPublicKey();
        } catch (ClassCastException var2) {
            throw new TlsFatalAlert((short)46, var2);
        }
    }

    DSAPublicKey getPubKeyDSS() throws IOException {
        try {
            return (DSAPublicKey)this.getPublicKey();
        } catch (ClassCastException var2) {
            throw new TlsFatalAlert((short)46, var2);
        }
    }

    ECPublicKey getPubKeyEC() throws IOException {
        try {
            return (ECPublicKey)this.getPublicKey();
        } catch (ClassCastException var2) {
            throw new TlsFatalAlert((short)46, var2);
        }
    }

    PublicKey getPubKeyEd25519() throws IOException {
        PublicKey publicKey = this.getPublicKey();
        if (!"Ed25519".equals(publicKey.getAlgorithm())) {
            throw new TlsFatalAlert((short)46);
        } else {
            return publicKey;
        }
    }

    PublicKey getPubKeyEd448() throws IOException {
        PublicKey publicKey = this.getPublicKey();
        if (!"Ed448".equals(publicKey.getAlgorithm())) {
            throw new TlsFatalAlert((short)46);
        } else {
            return publicKey;
        }
    }

    PublicKey getPubKeyRSA() throws IOException {
        return this.getPublicKey();
    }

    public short getLegacySignatureAlgorithm() throws IOException {
        PublicKey publicKey = this.getPublicKey();
        if (!this.supportsKeyUsageBit(0)) {
            return -1;
        } else if (publicKey instanceof RSAPublicKey) {
            return 1;
        } else if (publicKey instanceof DSAPublicKey) {
            return 2;
        } else {
            return (short)(publicKey instanceof ECPublicKey ? 3 : -1);
        }
    }

    public boolean supportsSignatureAlgorithm(short signatureAlgorithm) throws IOException {
        return !this.supportsKeyUsageBit(0) ? false : this.implSupportsSignatureAlgorithm(signatureAlgorithm);
    }

    public boolean supportsSignatureAlgorithmCA(short signatureAlgorithm) throws IOException {
        return this.implSupportsSignatureAlgorithm(signatureAlgorithm);
    }

    public TlsCertificate checkUsageInRole(int tlsCertificateRole) throws IOException {
        switch(tlsCertificateRole) {
            case 1:
                this.validateKeyUsageBit(4);
                this.pubKeyDH = this.getPubKeyDH();
                return this;
            case 2:
                this.validateKeyUsageBit(4);
                this.pubKeyEC = this.getPubKeyEC();
                return this;
            default:
                throw new TlsFatalAlert((short)46);
        }
    }

    protected boolean implSupportsSignatureAlgorithm(short signatureAlgorithm) throws IOException {
        PublicKey publicKey = this.getPublicKey();
        switch(signatureAlgorithm) {
            case 1:
                return this.supportsRSA_PKCS1() && publicKey instanceof RSAPublicKey;
            case 2:
                return publicKey instanceof DSAPublicKey;
            case 3:
            case 26:
            case 27:
            case 28:
                return publicKey instanceof ECPublicKey;
            case 4:
            case 5:
            case 6:
                return this.supportsRSA_PSS_RSAE() && publicKey instanceof RSAPublicKey;
            case 7:
                return "Ed25519".equals(publicKey.getAlgorithm());
            case 8:
                return "Ed448".equals(publicKey.getAlgorithm());
            case 9:
            case 10:
            case 11:
                return this.supportsRSA_PSS_PSS(signatureAlgorithm) && publicKey instanceof RSAPublicKey;
            case 12:
            case 13:
            case 14:
            case 15:
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
            case 21:
            case 22:
            case 23:
            case 24:
            case 25:
            default:
                return false;
        }
    }

    protected PublicKey getPublicKey() throws IOException {
        try {
            return this.certificate.getPublicKey();
        } catch (RuntimeException var2) {
            throw new TlsFatalAlert((short)42, var2);
        }
    }

    protected SubjectPublicKeyInfo getSubjectPublicKeyInfo() throws IOException {
        return SubjectPublicKeyInfo.getInstance(this.getPublicKey().getEncoded());
    }

    public X509Certificate getX509Certificate() {
        return this.certificate;
    }

    protected boolean supportsKeyUsageBit(int keyUsageBit) {
        boolean[] keyUsage = this.certificate.getKeyUsage();
        return null == keyUsage || keyUsage.length > keyUsageBit && keyUsage[keyUsageBit];
    }

    protected boolean supportsRSA_PKCS1() throws IOException {
        AlgorithmIdentifier pubKeyAlgID = this.getSubjectPublicKeyInfo().getAlgorithm();
        return RSAUtil.supportsPKCS1(pubKeyAlgID);
    }

    protected boolean supportsRSA_PSS_PSS(short signatureAlgorithm) throws IOException {
        AlgorithmIdentifier pubKeyAlgID = this.getSubjectPublicKeyInfo().getAlgorithm();
        return RSAUtil.supportsPSS_PSS(signatureAlgorithm, pubKeyAlgID);
    }

    protected boolean supportsRSA_PSS_RSAE() throws IOException {
        AlgorithmIdentifier pubKeyAlgID = this.getSubjectPublicKeyInfo().getAlgorithm();
        return RSAUtil.supportsPSS_RSAE(pubKeyAlgID);
    }

    protected void validateKeyUsageBit(int keyUsageBit) throws IOException {
        if (!this.supportsKeyUsageBit(keyUsageBit)) {
            throw new TlsFatalAlert((short)46);
        }
    }

    protected void validateRSA_PKCS1() throws IOException {
        if (!this.supportsRSA_PKCS1()) {
            throw new TlsFatalAlert((short)46);
        }
    }

    protected void validateRSA_PSS_PSS(short signatureAlgorithm) throws IOException {
        if (!this.supportsRSA_PSS_PSS(signatureAlgorithm)) {
            throw new TlsFatalAlert((short)46);
        }
    }

    protected void validateRSA_PSS_RSAE() throws IOException {
        if (!this.supportsRSA_PSS_RSAE()) {
            throw new TlsFatalAlert((short)46);
        }
    }
}

