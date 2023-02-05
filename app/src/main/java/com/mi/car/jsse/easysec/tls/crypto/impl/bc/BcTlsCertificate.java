package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.Certificate;
import com.mi.car.jsse.easysec.asn1.x509.Extension;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;
import com.mi.car.jsse.easysec.asn1.x509.KeyUsage;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.crypto.params.DHPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.DSAPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed25519PublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed448PublicKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.RSAKeyParameters;
import com.mi.car.jsse.easysec.crypto.util.PublicKeyFactory;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsEncryptor;
import com.mi.car.jsse.easysec.tls.crypto.TlsVerifier;
import com.mi.car.jsse.easysec.tls.crypto.impl.RSAUtil;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.math.BigInteger;



public class BcTlsCertificate implements TlsCertificate {
    protected final BcTlsCrypto crypto;
    protected final Certificate certificate;
    protected DHPublicKeyParameters pubKeyDH;
    protected ECPublicKeyParameters pubKeyEC;
    protected Ed25519PublicKeyParameters pubKeyEd25519;
    protected Ed448PublicKeyParameters pubKeyEd448;
    protected RSAKeyParameters pubKeyRSA;

    public static BcTlsCertificate convert(BcTlsCrypto crypto, TlsCertificate certificate) throws IOException {
        return certificate instanceof BcTlsCertificate ? (BcTlsCertificate)certificate : new BcTlsCertificate(crypto, certificate.getEncoded());
    }

    public static Certificate parseCertificate(byte[] encoding) throws IOException {
        try {
            ASN1Primitive asn1 = TlsUtils.readASN1Object(encoding);
            return Certificate.getInstance(asn1);
        } catch (IllegalArgumentException var2) {
            throw new TlsFatalAlert((short)42, var2);
        }
    }

    public BcTlsCertificate(BcTlsCrypto crypto, byte[] encoding) throws IOException {
        this(crypto, parseCertificate(encoding));
    }

    public BcTlsCertificate(BcTlsCrypto crypto, Certificate certificate) {
        this.pubKeyDH = null;
        this.pubKeyEC = null;
        this.pubKeyEd25519 = null;
        this.pubKeyEd448 = null;
        this.pubKeyRSA = null;
        this.crypto = crypto;
        this.certificate = certificate;
    }

    public TlsEncryptor createEncryptor(int tlsCertificateRole) throws IOException {
        this.validateKeyUsage(32);
        switch(tlsCertificateRole) {
            case 3:
                this.pubKeyRSA = this.getPubKeyRSA();
                return new BcTlsRSAEncryptor(this.crypto, this.pubKeyRSA);
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
                this.validateKeyUsage(128);
                switch(signatureAlgorithm) {
                    case 1:
                        this.validateRSA_PKCS1();
                        return new BcTlsRSAVerifier(this.crypto, this.getPubKeyRSA());
                    case 2:
                        return new BcTlsDSAVerifier(this.crypto, this.getPubKeyDSS());
                    case 3:
                        return new BcTlsECDSAVerifier(this.crypto, this.getPubKeyEC());
                    default:
                        throw new TlsFatalAlert((short)46);
                }
        }
    }

    public TlsVerifier createVerifier(int signatureScheme) throws IOException {
        this.validateKeyUsage(128);
        switch(signatureScheme) {
            case 513:
            case 1025:
            case 1281:
            case 1537:
                this.validateRSA_PKCS1();
                return new BcTlsRSAVerifier(this.crypto, this.getPubKeyRSA());
            case 515:
            case 1027:
            case 1283:
            case 1539:
            case 2074:
            case 2075:
            case 2076:
                return new BcTlsECDSA13Verifier(this.crypto, this.getPubKeyEC(), signatureScheme);
            case 2052:
            case 2053:
            case 2054:
                this.validateRSA_PSS_RSAE();
                return new BcTlsRSAPSSVerifier(this.crypto, this.getPubKeyRSA(), signatureScheme);
            case 2055:
                return new BcTlsEd25519Verifier(this.crypto, this.getPubKeyEd25519());
            case 2056:
                return new BcTlsEd448Verifier(this.crypto, this.getPubKeyEd448());
            case 2057:
            case 2058:
            case 2059:
                this.validateRSA_PSS_PSS(SignatureScheme.getSignatureAlgorithm(signatureScheme));
                return new BcTlsRSAPSSVerifier(this.crypto, this.getPubKeyRSA(), signatureScheme);
            default:
                throw new TlsFatalAlert((short)46);
        }
    }

    public byte[] getEncoded() throws IOException {
        return this.certificate.getEncoded("DER");
    }

    public byte[] getExtension(ASN1ObjectIdentifier extensionOID) throws IOException {
        Extensions extensions = this.certificate.getTBSCertificate().getExtensions();
        if (extensions != null) {
            Extension extension = extensions.getExtension(extensionOID);
            if (extension != null) {
                return Arrays.clone(extension.getExtnValue().getOctets());
            }
        }

        return null;
    }

    public BigInteger getSerialNumber() {
        return this.certificate.getSerialNumber().getValue();
    }

    public String getSigAlgOID() {
        return this.certificate.getSignatureAlgorithm().getAlgorithm().getId();
    }

    public ASN1Encodable getSigAlgParams() {
        return this.certificate.getSignatureAlgorithm().getParameters();
    }

    public short getLegacySignatureAlgorithm() throws IOException {
        AsymmetricKeyParameter publicKey = this.getPublicKey();
        if (publicKey.isPrivate()) {
            throw new TlsFatalAlert((short)80);
        } else if (!this.supportsKeyUsage(128)) {
            return -1;
        } else if (publicKey instanceof RSAKeyParameters) {
            return 1;
        } else if (publicKey instanceof DSAPublicKeyParameters) {
            return 2;
        } else {
            return (short)(publicKey instanceof ECPublicKeyParameters ? 3 : -1);
        }
    }

    public DHPublicKeyParameters getPubKeyDH() throws IOException {
        try {
            return (DHPublicKeyParameters)this.getPublicKey();
        } catch (ClassCastException var2) {
            throw new TlsFatalAlert((short)46, var2);
        }
    }

    public DSAPublicKeyParameters getPubKeyDSS() throws IOException {
        try {
            return (DSAPublicKeyParameters)this.getPublicKey();
        } catch (ClassCastException var2) {
            throw new TlsFatalAlert((short)46, var2);
        }
    }

    public ECPublicKeyParameters getPubKeyEC() throws IOException {
        try {
            return (ECPublicKeyParameters)this.getPublicKey();
        } catch (ClassCastException var2) {
            throw new TlsFatalAlert((short)46, var2);
        }
    }

    public Ed25519PublicKeyParameters getPubKeyEd25519() throws IOException {
        try {
            return (Ed25519PublicKeyParameters)this.getPublicKey();
        } catch (ClassCastException var2) {
            throw new TlsFatalAlert((short)46, var2);
        }
    }

    public Ed448PublicKeyParameters getPubKeyEd448() throws IOException {
        try {
            return (Ed448PublicKeyParameters)this.getPublicKey();
        } catch (ClassCastException var2) {
            throw new TlsFatalAlert((short)46, var2);
        }
    }

    public RSAKeyParameters getPubKeyRSA() throws IOException {
        try {
            return (RSAKeyParameters)this.getPublicKey();
        } catch (ClassCastException var2) {
            throw new TlsFatalAlert((short)46, var2);
        }
    }

    public boolean supportsSignatureAlgorithm(short signatureAlgorithm) throws IOException {
        return this.supportsSignatureAlgorithm(signatureAlgorithm, 128);
    }

    public boolean supportsSignatureAlgorithmCA(short signatureAlgorithm) throws IOException {
        return this.supportsSignatureAlgorithm(signatureAlgorithm, 4);
    }

    public TlsCertificate checkUsageInRole(int tlsCertificateRole) throws IOException {
        switch(tlsCertificateRole) {
            case 1:
                this.validateKeyUsage(8);
                this.pubKeyDH = this.getPubKeyDH();
                return this;
            case 2:
                this.validateKeyUsage(8);
                this.pubKeyEC = this.getPubKeyEC();
                return this;
            default:
                throw new TlsFatalAlert((short)46);
        }
    }

    protected AsymmetricKeyParameter getPublicKey() throws IOException {
        SubjectPublicKeyInfo keyInfo = this.certificate.getSubjectPublicKeyInfo();

        try {
            return PublicKeyFactory.createKey(keyInfo);
        } catch (RuntimeException var3) {
            throw new TlsFatalAlert((short)43, var3);
        }
    }

    protected boolean supportsKeyUsage(int keyUsageBits) {
        Extensions exts = this.certificate.getTBSCertificate().getExtensions();
        if (exts != null) {
            KeyUsage ku = KeyUsage.fromExtensions(exts);
            if (ku != null) {
                int bits = ku.getBytes()[0] & 255;
                if ((bits & keyUsageBits) != keyUsageBits) {
                    return false;
                }
            }
        }

        return true;
    }

    protected boolean supportsRSA_PKCS1() {
        AlgorithmIdentifier pubKeyAlgID = this.certificate.getSubjectPublicKeyInfo().getAlgorithm();
        return RSAUtil.supportsPKCS1(pubKeyAlgID);
    }

    protected boolean supportsRSA_PSS_PSS(short signatureAlgorithm) {
        AlgorithmIdentifier pubKeyAlgID = this.certificate.getSubjectPublicKeyInfo().getAlgorithm();
        return RSAUtil.supportsPSS_PSS(signatureAlgorithm, pubKeyAlgID);
    }

    protected boolean supportsRSA_PSS_RSAE() {
        AlgorithmIdentifier pubKeyAlgID = this.certificate.getSubjectPublicKeyInfo().getAlgorithm();
        return RSAUtil.supportsPSS_RSAE(pubKeyAlgID);
    }

    protected boolean supportsSignatureAlgorithm(short signatureAlgorithm, int keyUsage) throws IOException {
        if (!this.supportsKeyUsage(keyUsage)) {
            return false;
        } else {
            AsymmetricKeyParameter publicKey = this.getPublicKey();
            switch(signatureAlgorithm) {
                case 1:
                    return this.supportsRSA_PKCS1() && publicKey instanceof RSAKeyParameters;
                case 2:
                    return publicKey instanceof DSAPublicKeyParameters;
                case 3:
                case 26:
                case 27:
                case 28:
                    return publicKey instanceof ECPublicKeyParameters;
                case 4:
                case 5:
                case 6:
                    return this.supportsRSA_PSS_RSAE() && publicKey instanceof RSAKeyParameters;
                case 7:
                    return publicKey instanceof Ed25519PublicKeyParameters;
                case 8:
                    return publicKey instanceof Ed448PublicKeyParameters;
                case 9:
                case 10:
                case 11:
                    return this.supportsRSA_PSS_PSS(signatureAlgorithm) && publicKey instanceof RSAKeyParameters;
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
    }

    public void validateKeyUsage(int keyUsageBits) throws IOException {
        if (!this.supportsKeyUsage(keyUsageBits)) {
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