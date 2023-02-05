package com.mi.car.jsse.easysec.jce;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Encoding;
import com.mi.car.jsse.easysec.asn1.ASN1InputStream;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.CertificationRequest;
import com.mi.car.jsse.easysec.asn1.pkcs.CertificationRequestInfo;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.RSASSAPSSparams;
import com.mi.car.jsse.easysec.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.X509Name;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.jce.provider.EasysecProvider;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

public class PKCS10CertificationRequest extends CertificationRequest {
    private static Hashtable algorithms = new Hashtable();
    private static Hashtable keyAlgorithms = new Hashtable();
    private static Set noParams = new HashSet();
    private static Hashtable oids = new Hashtable();
    private static Hashtable params = new Hashtable();

    static {
        algorithms.put("MD2WITHRSAENCRYPTION", new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"));
        algorithms.put("MD2WITHRSA", new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"));
        algorithms.put("MD5WITHRSAENCRYPTION", new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"));
        algorithms.put("MD5WITHRSA", new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"));
        algorithms.put("RSAWITHMD5", new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"));
        algorithms.put("SHA1WITHRSAENCRYPTION", new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"));
        algorithms.put("SHA1WITHRSA", new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"));
        algorithms.put("SHA224WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        algorithms.put("SHA224WITHRSA", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        algorithms.put("SHA256WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        algorithms.put("SHA256WITHRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        algorithms.put("SHA384WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        algorithms.put("SHA384WITHRSA", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        algorithms.put("SHA512WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        algorithms.put("SHA512WITHRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        algorithms.put("SHA1WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA224WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA256WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA384WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA512WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("RSAWITHSHA1", new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"));
        algorithms.put("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        algorithms.put("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        algorithms.put("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        algorithms.put("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        algorithms.put("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        algorithms.put("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        algorithms.put("SHA1WITHDSA", new ASN1ObjectIdentifier("1.2.840.10040.4.3"));
        algorithms.put("DSAWITHSHA1", new ASN1ObjectIdentifier("1.2.840.10040.4.3"));
        algorithms.put("SHA224WITHDSA", NISTObjectIdentifiers.dsa_with_sha224);
        algorithms.put("SHA256WITHDSA", NISTObjectIdentifiers.dsa_with_sha256);
        algorithms.put("SHA384WITHDSA", NISTObjectIdentifiers.dsa_with_sha384);
        algorithms.put("SHA512WITHDSA", NISTObjectIdentifiers.dsa_with_sha512);
        algorithms.put("SHA1WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA1);
        algorithms.put("SHA224WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA224);
        algorithms.put("SHA256WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA256);
        algorithms.put("SHA384WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA384);
        algorithms.put("SHA512WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA512);
        algorithms.put("ECDSAWITHSHA1", X9ObjectIdentifiers.ecdsa_with_SHA1);
        algorithms.put("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        algorithms.put("GOST3410WITHGOST3411", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        algorithms.put("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        algorithms.put("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        algorithms.put("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), "SHA1WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA");
        oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410");
        oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410");
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"), "MD5WITHRSA");
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"), "MD2WITHRSA");
        oids.put(new ASN1ObjectIdentifier("1.2.840.10040.4.3"), "SHA1WITHDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA");
        oids.put(OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
        oids.put(OIWObjectIdentifiers.dsaWithSHA1, "SHA1WITHDSA");
        oids.put(NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA");
        oids.put(NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA");
        keyAlgorithms.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        keyAlgorithms.put(X9ObjectIdentifiers.id_dsa, "DSA");
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA1);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA224);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA256);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA384);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA512);
        noParams.add(X9ObjectIdentifiers.id_dsa_with_sha1);
        noParams.add(OIWObjectIdentifiers.dsaWithSHA1);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha224);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha256);
        noParams.add(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        noParams.add(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        params.put("SHA1WITHRSAANDMGF1", creatPSSParams(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), 20));
        params.put("SHA224WITHRSAANDMGF1", creatPSSParams(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224, DERNull.INSTANCE), 28));
        params.put("SHA256WITHRSAANDMGF1", creatPSSParams(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE), 32));
        params.put("SHA384WITHRSAANDMGF1", creatPSSParams(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE), 48));
        params.put("SHA512WITHRSAANDMGF1", creatPSSParams(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE), 64));
    }

    private static RSASSAPSSparams creatPSSParams(AlgorithmIdentifier hashAlgId, int saltSize) {
        return new RSASSAPSSparams(hashAlgId, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hashAlgId), new ASN1Integer((long) saltSize), new ASN1Integer(1));
    }

    private static ASN1Sequence toDERSequence(byte[] bytes) {
        try {
            return (ASN1Sequence) new ASN1InputStream(bytes).readObject();
        } catch (Exception e) {
            throw new IllegalArgumentException("badly encoded request");
        }
    }

    public PKCS10CertificationRequest(byte[] bytes) {
        super(toDERSequence(bytes));
    }

    public PKCS10CertificationRequest(ASN1Sequence sequence) {
        super(sequence);
    }

    public PKCS10CertificationRequest(String signatureAlgorithm, X509Name subject, PublicKey key, ASN1Set attributes, PrivateKey signingKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        this(signatureAlgorithm, subject, key, attributes, signingKey, EasysecProvider.PROVIDER_NAME);
    }

    private static X509Name convertName(X500Principal name) {
        try {
            return new X509Principal(name.getEncoded());
        } catch (IOException e) {
            throw new IllegalArgumentException("can't convert name");
        }
    }

    public PKCS10CertificationRequest(String signatureAlgorithm, X500Principal subject, PublicKey key, ASN1Set attributes, PrivateKey signingKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        this(signatureAlgorithm, convertName(subject), key, attributes, signingKey, EasysecProvider.PROVIDER_NAME);
    }

    public PKCS10CertificationRequest(String signatureAlgorithm, X500Principal subject, PublicKey key, ASN1Set attributes, PrivateKey signingKey, String provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        this(signatureAlgorithm, convertName(subject), key, attributes, signingKey, provider);
    }

    public PKCS10CertificationRequest(String signatureAlgorithm, X509Name subject, PublicKey key, ASN1Set attributes, PrivateKey signingKey, String provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature sig;
        String algorithmName = Strings.toUpperCase(signatureAlgorithm);
        ASN1ObjectIdentifier sigOID = (ASN1ObjectIdentifier) algorithms.get(algorithmName);
        if (sigOID == null) {
            try {
                sigOID = new ASN1ObjectIdentifier(algorithmName);
            } catch (Exception e) {
                throw new IllegalArgumentException("Unknown signature type requested");
            }
        }
        if (subject == null) {
            throw new IllegalArgumentException("subject must not be null");
        } else if (key == null) {
            throw new IllegalArgumentException("public key must not be null");
        } else {
            if (noParams.contains(sigOID)) {
                this.sigAlgId = new AlgorithmIdentifier(sigOID);
            } else if (params.containsKey(algorithmName)) {
                this.sigAlgId = new AlgorithmIdentifier(sigOID, (ASN1Encodable) params.get(algorithmName));
            } else {
                this.sigAlgId = new AlgorithmIdentifier(sigOID, DERNull.INSTANCE);
            }
            try {
                this.reqInfo = new CertificationRequestInfo(subject, SubjectPublicKeyInfo.getInstance((ASN1Sequence) ASN1Primitive.fromByteArray(key.getEncoded())), attributes);
                if (provider == null) {
                    sig = Signature.getInstance(signatureAlgorithm);
                } else {
                    sig = Signature.getInstance(signatureAlgorithm, provider);
                }
                sig.initSign(signingKey);
                try {
                    sig.update(this.reqInfo.getEncoded(ASN1Encoding.DER));
                    this.sigBits = new DERBitString(sig.sign());
                } catch (Exception e2) {
                    throw new IllegalArgumentException("exception encoding TBS cert request - " + e2);
                }
            } catch (IOException e3) {
                throw new IllegalArgumentException("can't encode public key");
            }
        }
    }

    public PublicKey getPublicKey() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        return getPublicKey(EasysecProvider.PROVIDER_NAME);
    }

    public PublicKey getPublicKey(String provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        SubjectPublicKeyInfo subjectPKInfo = this.reqInfo.getSubjectPublicKeyInfo();
        try {
            X509EncodedKeySpec xspec = new X509EncodedKeySpec(new DERBitString(subjectPKInfo).getOctets());
            AlgorithmIdentifier keyAlg = subjectPKInfo.getAlgorithm();
            if (provider != null) {
                return KeyFactory.getInstance(keyAlg.getAlgorithm().getId(), provider).generatePublic(xspec);
            }
            try {
                return KeyFactory.getInstance(keyAlg.getAlgorithm().getId()).generatePublic(xspec);
            } catch (NoSuchAlgorithmException e) {
                if (keyAlgorithms.get(keyAlg.getAlgorithm()) != null) {
                    String keyAlgorithm = (String) keyAlgorithms.get(keyAlg.getAlgorithm());
                    if (provider == null) {
                        return KeyFactory.getInstance(keyAlgorithm).generatePublic(xspec);
                    }
                    return KeyFactory.getInstance(keyAlgorithm, provider).generatePublic(xspec);
                }
                throw e;
            }
        } catch (InvalidKeySpecException e2) {
            throw new InvalidKeyException("error decoding public key");
        } catch (IOException e3) {
            throw new InvalidKeyException("error decoding public key");
        }
    }

    public boolean verify() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        return verify(EasysecProvider.PROVIDER_NAME);
    }

    public boolean verify(String provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        return verify(getPublicKey(provider), provider);
    }

    public boolean verify(PublicKey pubKey, String provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature sig;
        if (provider == null) {
            try {
                sig = Signature.getInstance(getSignatureName(this.sigAlgId));
            } catch (NoSuchAlgorithmException e) {
                if (oids.get(this.sigAlgId.getAlgorithm()) != null) {
                    String signatureAlgorithm = (String) oids.get(this.sigAlgId.getAlgorithm());
                    if (provider == null) {
                        sig = Signature.getInstance(signatureAlgorithm);
                    } else {
                        sig = Signature.getInstance(signatureAlgorithm, provider);
                    }
                } else {
                    throw e;
                }
            }
        } else {
            sig = Signature.getInstance(getSignatureName(this.sigAlgId), provider);
        }
        setSignatureParameters(sig, this.sigAlgId.getParameters());
        sig.initVerify(pubKey);
        try {
            sig.update(this.reqInfo.getEncoded(ASN1Encoding.DER));
            return sig.verify(this.sigBits.getOctets());
        } catch (Exception e2) {
            throw new SignatureException("exception encoding TBS cert request - " + e2);
        }
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.util.Encodable
    public byte[] getEncoded() {
        try {
            return getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new RuntimeException(e.toString());
        }
    }

    private void setSignatureParameters(Signature signature, ASN1Encodable params2) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        if (params2 != null && !DERNull.INSTANCE.equals(params2)) {
            AlgorithmParameters sigParams = AlgorithmParameters.getInstance(signature.getAlgorithm(), signature.getProvider());
            try {
                sigParams.init(params2.toASN1Primitive().getEncoded(ASN1Encoding.DER));
                if (signature.getAlgorithm().endsWith("MGF1")) {
                    try {
                        signature.setParameter(sigParams.getParameterSpec(PSSParameterSpec.class));
                    } catch (GeneralSecurityException e) {
                        throw new SignatureException("Exception extracting parameters: " + e.getMessage());
                    }
                }
            } catch (IOException e2) {
                throw new SignatureException("IOException decoding parameters: " + e2.getMessage());
            }
        }
    }

    static String getSignatureName(AlgorithmIdentifier sigAlgId) {
        ASN1Encodable params2 = sigAlgId.getParameters();
        if (params2 == null || DERNull.INSTANCE.equals(params2) || !sigAlgId.getAlgorithm().equals((ASN1Primitive) PKCSObjectIdentifiers.id_RSASSA_PSS)) {
            return sigAlgId.getAlgorithm().getId();
        }
        return getDigestAlgName(RSASSAPSSparams.getInstance(params2).getHashAlgorithm().getAlgorithm()) + "withRSAandMGF1";
    }

    private static String getDigestAlgName(ASN1ObjectIdentifier digestAlgOID) {
        if (PKCSObjectIdentifiers.md5.equals((ASN1Primitive) digestAlgOID)) {
            return "MD5";
        }
        if (OIWObjectIdentifiers.idSHA1.equals((ASN1Primitive) digestAlgOID)) {
            return "SHA1";
        }
        if (NISTObjectIdentifiers.id_sha224.equals((ASN1Primitive) digestAlgOID)) {
            return "SHA224";
        }
        if (NISTObjectIdentifiers.id_sha256.equals((ASN1Primitive) digestAlgOID)) {
            return "SHA256";
        }
        if (NISTObjectIdentifiers.id_sha384.equals((ASN1Primitive) digestAlgOID)) {
            return "SHA384";
        }
        if (NISTObjectIdentifiers.id_sha512.equals((ASN1Primitive) digestAlgOID)) {
            return "SHA512";
        }
        if (TeleTrusTObjectIdentifiers.ripemd128.equals((ASN1Primitive) digestAlgOID)) {
            return "RIPEMD128";
        }
        if (TeleTrusTObjectIdentifiers.ripemd160.equals((ASN1Primitive) digestAlgOID)) {
            return "RIPEMD160";
        }
        if (TeleTrusTObjectIdentifiers.ripemd256.equals((ASN1Primitive) digestAlgOID)) {
            return "RIPEMD256";
        }
        if (CryptoProObjectIdentifiers.gostR3411.equals((ASN1Primitive) digestAlgOID)) {
            return "GOST3411";
        }
        return digestAlgOID.getId();
    }
}
