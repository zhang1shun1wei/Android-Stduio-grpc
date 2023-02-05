package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.tls.CipherSuite;
import com.mi.car.jsse.easysec.tls.DigitallySigned;
import com.mi.car.jsse.easysec.tls.NamedGroup;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.TlsDHUtils;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.SRP6Group;
import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsCipher;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoException;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsDHConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsDHDomain;
import com.mi.car.jsse.easysec.tls.crypto.TlsECConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsECDomain;
import com.mi.car.jsse.easysec.tls.crypto.TlsHMAC;
import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import com.mi.car.jsse.easysec.tls.crypto.TlsNonceGenerator;
import com.mi.car.jsse.easysec.tls.crypto.TlsSRP6Client;
import com.mi.car.jsse.easysec.tls.crypto.TlsSRP6Server;
import com.mi.car.jsse.easysec.tls.crypto.TlsSRP6VerifierGenerator;
import com.mi.car.jsse.easysec.tls.crypto.TlsSRPConfig;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamSigner;
import com.mi.car.jsse.easysec.tls.crypto.TlsStreamVerifier;
import com.mi.car.jsse.easysec.tls.crypto.impl.AbstractTlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipher;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipherImpl;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipher;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipherImpl;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsImplUtils;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsNullCipher;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.srp.SRP6Client;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.srp.SRP6Server;
import com.mi.car.jsse.easysec.tls.crypto.impl.jcajce.srp.SRP6VerifierGenerator;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Integers;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

public class JcaTlsCrypto extends AbstractTlsCrypto {
    private final JcaJceHelper helper;
    private final SecureRandom entropySource;
    private final SecureRandom nonceEntropySource;
    private final Hashtable supportedEncryptionAlgorithms = new Hashtable();
    private final Hashtable supportedNamedGroups = new Hashtable();
    private final Hashtable supportedOther = new Hashtable();

    protected JcaTlsCrypto(JcaJceHelper helper, SecureRandom entropySource, SecureRandom nonceEntropySource) {
        this.helper = helper;
        this.entropySource = entropySource;
        this.nonceEntropySource = nonceEntropySource;
    }

    JceTlsSecret adoptLocalSecret(byte[] data) {
        return new JceTlsSecret(this, data);
    }

    Cipher createRSAEncryptionCipher() throws GeneralSecurityException {
        try {
            return this.getHelper().createCipher("RSA/NONE/PKCS1Padding");
        } catch (GeneralSecurityException var2) {
            return this.getHelper().createCipher("RSA/ECB/PKCS1Padding");
        }
    }

    public TlsNonceGenerator createNonceGenerator(byte[] additionalSeedMaterial) {
        return new JcaNonceGenerator(this.nonceEntropySource, additionalSeedMaterial);
    }

    public SecureRandom getSecureRandom() {
        return this.entropySource;
    }

    public byte[] calculateKeyAgreement(String agreementAlgorithm, PrivateKey privateKey, PublicKey publicKey, String secretAlgorithm) throws GeneralSecurityException {
        KeyAgreement agreement = this.helper.createKeyAgreement(agreementAlgorithm);
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);

        try {
            return agreement.generateSecret(secretAlgorithm).getEncoded();
        } catch (NoSuchAlgorithmException var7) {
            if (!"X25519".equals(agreementAlgorithm) && !"X448".equals(agreementAlgorithm)) {
                throw var7;
            } else {
                return agreement.generateSecret();
            }
        }
    }

    public TlsCertificate createCertificate(byte[] encoding) throws IOException {
        return new JcaTlsCertificate(this, encoding);
    }

    public TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm) throws IOException {
        try {
            switch(encryptionAlgorithm) {
                case 0:
                    return this.createNullCipher(cryptoParams, macAlgorithm);
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                default:
                    throw new TlsFatalAlert((short)80);
                case 7:
                    return this.createCipher_CBC(cryptoParams, "DESede", 24, macAlgorithm);
                case 8:
                    return this.createCipher_CBC(cryptoParams, "AES", 16, macAlgorithm);
                case 9:
                    return this.createCipher_CBC(cryptoParams, "AES", 32, macAlgorithm);
                case 10:
                    return this.createCipher_AES_GCM(cryptoParams, 16, 16);
                case 11:
                    return this.createCipher_AES_GCM(cryptoParams, 32, 16);
                case 12:
                    return this.createCipher_CBC(cryptoParams, "Camellia", 16, macAlgorithm);
                case 13:
                    return this.createCipher_CBC(cryptoParams, "Camellia", 32, macAlgorithm);
                case 14:
                    return this.createCipher_CBC(cryptoParams, "SEED", 16, macAlgorithm);
                case 15:
                    return this.createCipher_AES_CCM(cryptoParams, 16, 16);
                case 16:
                    return this.createCipher_AES_CCM(cryptoParams, 16, 8);
                case 17:
                    return this.createCipher_AES_CCM(cryptoParams, 32, 16);
                case 18:
                    return this.createCipher_AES_CCM(cryptoParams, 32, 8);
                case 19:
                    return this.createCipher_Camellia_GCM(cryptoParams, 16, 16);
                case 20:
                    return this.createCipher_Camellia_GCM(cryptoParams, 32, 16);
                case 21:
                    return this.createChaCha20Poly1305(cryptoParams);
                case 22:
                    return this.createCipher_CBC(cryptoParams, "ARIA", 16, macAlgorithm);
                case 23:
                    return this.createCipher_CBC(cryptoParams, "ARIA", 32, macAlgorithm);
                case 24:
                    return this.createCipher_ARIA_GCM(cryptoParams, 16, 16);
                case 25:
                    return this.createCipher_ARIA_GCM(cryptoParams, 32, 16);
                case 26:
                    return this.createCipher_SM4_CCM(cryptoParams);
                case 27:
                    return this.createCipher_SM4_GCM(cryptoParams);
                case 28:
                    return this.createCipher_CBC(cryptoParams, "SM4", 16, macAlgorithm);
            }
        } catch (GeneralSecurityException var5) {
            throw new TlsCryptoException("cannot create cipher: " + var5.getMessage(), var5);
        }
    }

    public TlsHMAC createHMAC(int macAlgorithm) {
        return this.createHMACForHash(TlsCryptoUtils.getHashForHMAC(macAlgorithm));
    }

    public TlsHMAC createHMACForHash(int cryptoHashAlgorithm) {
        String hmacName = this.getHMACAlgorithmName(cryptoHashAlgorithm);

        try {
            return new JceTlsHMAC(cryptoHashAlgorithm, this.helper.createMac(hmacName), hmacName);
        } catch (GeneralSecurityException var4) {
            throw new RuntimeException("cannot create HMAC: " + hmacName, var4);
        }
    }

    protected TlsHMAC createHMAC_SSL(int macAlgorithm) throws GeneralSecurityException, IOException {
        switch(macAlgorithm) {
            case 1:
                return new JcaSSL3HMAC(this.createHash(this.getDigestName(1)), 16, 64);
            case 2:
                return new JcaSSL3HMAC(this.createHash(this.getDigestName(2)), 20, 64);
            case 3:
                return new JcaSSL3HMAC(this.createHash(this.getDigestName(4)), 32, 64);
            case 4:
                return new JcaSSL3HMAC(this.createHash(this.getDigestName(5)), 48, 128);
            case 5:
                return new JcaSSL3HMAC(this.createHash(this.getDigestName(6)), 64, 128);
            default:
                throw new TlsFatalAlert((short)80);
        }
    }

    protected TlsHMAC createMAC(TlsCryptoParameters cryptoParams, int macAlgorithm) throws GeneralSecurityException, IOException {
        return TlsImplUtils.isSSL(cryptoParams) ? this.createHMAC_SSL(macAlgorithm) : this.createHMAC(macAlgorithm);
    }

    public TlsSRP6Client createSRP6Client(TlsSRPConfig srpConfig) {
        final SRP6Client srpClient = new SRP6Client();
        BigInteger[] ng = srpConfig.getExplicitNG();
        SRP6Group srpGroup = new SRP6Group(ng[0], ng[1]);
        srpClient.init(srpGroup, this.createHash(2), this.getSecureRandom());
        return new TlsSRP6Client() {
            public BigInteger calculateSecret(BigInteger serverB) throws TlsFatalAlert {
                try {
                    return srpClient.calculateSecret(serverB);
                } catch (IllegalArgumentException var3) {
                    throw new TlsFatalAlert((short)47, var3);
                }
            }

            public BigInteger generateClientCredentials(byte[] srpSalt, byte[] identity, byte[] password) {
                return srpClient.generateClientCredentials(srpSalt, identity, password);
            }
        };
    }

    public TlsSRP6Server createSRP6Server(TlsSRPConfig srpConfig, BigInteger srpVerifier) {
        final SRP6Server srpServer = new SRP6Server();
        BigInteger[] ng = srpConfig.getExplicitNG();
        SRP6Group srpGroup = new SRP6Group(ng[0], ng[1]);
        srpServer.init(srpGroup, srpVerifier, this.createHash(2), this.getSecureRandom());
        return new TlsSRP6Server() {
            public BigInteger generateServerCredentials() {
                return srpServer.generateServerCredentials();
            }

            public BigInteger calculateSecret(BigInteger clientA) throws IOException {
                try {
                    return srpServer.calculateSecret(clientA);
                } catch (IllegalArgumentException var3) {
                    throw new TlsFatalAlert((short)47, var3);
                }
            }
        };
    }

    public TlsSRP6VerifierGenerator createSRP6VerifierGenerator(TlsSRPConfig srpConfig) {
        BigInteger[] ng = srpConfig.getExplicitNG();
        final SRP6VerifierGenerator verifierGenerator = new SRP6VerifierGenerator();
        verifierGenerator.init(ng[0], ng[1], this.createHash(2));
        return new TlsSRP6VerifierGenerator() {
            public BigInteger generateVerifier(byte[] salt, byte[] identity, byte[] password) {
                return verifierGenerator.generateVerifier(salt, identity, password);
            }
        };
    }

    String getHMACAlgorithmName(int cryptoHashAlgorithm) {
        switch(cryptoHashAlgorithm) {
            case 1:
                return "HmacMD5";
            case 2:
                return "HmacSHA1";
            case 3:
                return "HmacSHA224";
            case 4:
                return "HmacSHA256";
            case 5:
                return "HmacSHA384";
            case 6:
                return "HmacSHA512";
            case 7:
                return "HmacSM3";
            default:
                throw new IllegalArgumentException("invalid CryptoHashAlgorithm: " + cryptoHashAlgorithm);
        }
    }

    public AlgorithmParameters getNamedGroupAlgorithmParameters(int namedGroup) throws GeneralSecurityException {
        if (NamedGroup.refersToAnXDHCurve(namedGroup)) {
            switch(namedGroup) {
                case 29:
                case 30:
                    return null;
            }
        } else {
            if (NamedGroup.refersToAnECDSACurve(namedGroup)) {
                return ECUtil.getAlgorithmParameters(this, NamedGroup.getCurveName(namedGroup));
            }

            if (NamedGroup.refersToASpecificFiniteField(namedGroup)) {
                return DHUtil.getAlgorithmParameters(this, TlsDHUtils.getNamedDHGroup(namedGroup));
            }
        }

        throw new IllegalArgumentException("NamedGroup not supported: " + NamedGroup.getText(namedGroup));
    }

    public AlgorithmParameters getSignatureSchemeAlgorithmParameters(int signatureScheme) throws GeneralSecurityException {
        if (!SignatureScheme.isRSAPSS(signatureScheme)) {
            return null;
        } else {
            int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
            if (cryptoHashAlgorithm < 0) {
                return null;
            } else {
                String digestName = this.getDigestName(cryptoHashAlgorithm);
                String sigName = RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1";
                AlgorithmParameterSpec pssSpec = RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm, digestName, this.getHelper());
                Signature signer = this.getHelper().createSignature(sigName);
                signer.setParameter(pssSpec);
                return signer.getParameters();
            }
        }
    }

    public boolean hasAllRawSignatureAlgorithms() {
        return !JcaUtils.isSunMSCAPIProviderActive() && !this.hasSignatureAlgorithm((short)7) && !this.hasSignatureAlgorithm((short)8);
    }

    public boolean hasDHAgreement() {
        return true;
    }

    public boolean hasECDHAgreement() {
        return true;
    }

    public boolean hasEncryptionAlgorithm(int encryptionAlgorithm) {
        Integer key = Integers.valueOf(encryptionAlgorithm);
        synchronized(this.supportedEncryptionAlgorithms) {
            Boolean cached = (Boolean)this.supportedEncryptionAlgorithms.get(key);
            if (cached != null) {
                return cached;
            }
        }

        Boolean supported = this.isSupportedEncryptionAlgorithm(encryptionAlgorithm);
        if (null == supported) {
            return false;
        } else {
            synchronized(this.supportedEncryptionAlgorithms) {
                Boolean cached = (Boolean)this.supportedEncryptionAlgorithms.put(key, supported);
                if (null != cached && supported != cached) {
                    this.supportedEncryptionAlgorithms.put(key, cached);
                    supported = cached;
                }
            }

            return supported;
        }
    }

    public boolean hasCryptoHashAlgorithm(int cryptoHashAlgorithm) {
        return true;
    }

    public boolean hasCryptoSignatureAlgorithm(int cryptoSignatureAlgorithm) {
        switch(cryptoSignatureAlgorithm) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
                return true;
            case 64:
            case 65:
            case 200:
            default:
                return false;
        }
    }

    public boolean hasMacAlgorithm(int macAlgorithm) {
        return true;
    }

    public boolean hasNamedGroup(int namedGroup) {
        Integer key = Integers.valueOf(namedGroup);
        synchronized(this.supportedNamedGroups) {
            Boolean cached = (Boolean)this.supportedNamedGroups.get(key);
            if (null != cached) {
                return cached;
            }
        }

        Boolean supported = this.isSupportedNamedGroup(namedGroup);
        if (null == supported) {
            return false;
        } else {
            synchronized(this.supportedNamedGroups) {
                Boolean cached = (Boolean)this.supportedNamedGroups.put(key, supported);
                if (null != cached && supported != cached) {
                    this.supportedNamedGroups.put(key, cached);
                    supported = cached;
                }
            }

            return supported;
        }
    }

    public boolean hasRSAEncryption() {
        String key = "KE_RSA";
        synchronized(this.supportedOther) {
            Boolean cached = (Boolean)this.supportedOther.get("KE_RSA");
            if (cached != null) {
                return cached;
            }
        }

        Boolean supported;
        try {
            this.createRSAEncryptionCipher();
            supported = Boolean.TRUE;
        } catch (GeneralSecurityException var6) {
            supported = Boolean.FALSE;
        }

        synchronized(this.supportedOther) {
            Boolean cached = (Boolean)this.supportedOther.put("KE_RSA", supported);
            if (null != cached && supported != cached) {
                this.supportedOther.put("KE_RSA", cached);
                supported = cached;
            }
        }

        return supported;
    }

    public boolean hasSignatureAlgorithm(short signatureAlgorithm) {
        switch(signatureAlgorithm) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
            case 26:
            case 27:
            case 28:
                return true;
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
            case 29:
            case 30:
            case 31:
            case 32:
            case 33:
            case 34:
            case 35:
            case 36:
            case 37:
            case 38:
            case 39:
            case 40:
            case 41:
            case 42:
            case 43:
            case 44:
            case 45:
            case 46:
            case 47:
            case 48:
            case 49:
            case 50:
            case 51:
            case 52:
            case 53:
            case 54:
            case 55:
            case 56:
            case 57:
            case 58:
            case 59:
            case 60:
            case 61:
            case 62:
            case 63:
            case 64:
            case 65:
            default:
                return false;
        }
    }

    public boolean hasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm) {
        short signature = sigAndHashAlgorithm.getSignature();
        switch(sigAndHashAlgorithm.getHash()) {
            case 1:
                return 1 == signature && this.hasSignatureAlgorithm(signature);
            case 3:
                return !JcaUtils.isSunMSCAPIProviderActive() && this.hasSignatureAlgorithm(signature);
            default:
                return this.hasSignatureAlgorithm(signature);
        }
    }

    public boolean hasSignatureScheme(int signatureScheme) {
        switch(signatureScheme) {
            case 1800:
                return false;
            default:
                short signature = SignatureScheme.getSignatureAlgorithm(signatureScheme);
                switch(SignatureScheme.getCryptoHashAlgorithm(signatureScheme)) {
                    case 1:
                        return 1 == signature && this.hasSignatureAlgorithm(signature);
                    case 3:
                        return !JcaUtils.isSunMSCAPIProviderActive() && this.hasSignatureAlgorithm(signature);
                    default:
                        return this.hasSignatureAlgorithm(signature);
                }
        }
    }

    public boolean hasSRPAuthentication() {
        return true;
    }

    public TlsSecret createSecret(byte[] data) {
        return this.adoptLocalSecret(Arrays.clone(data));
    }

    public TlsSecret generateRSAPreMasterSecret(ProtocolVersion version) {
        byte[] data = new byte[48];
        this.getSecureRandom().nextBytes(data);
        TlsUtils.writeVersion(version, data, 0);
        return this.adoptLocalSecret(data);
    }

    public TlsHash createHash(int cryptoHashAlgorithm) {
        try {
            return this.createHash(this.getDigestName(cryptoHashAlgorithm));
        } catch (GeneralSecurityException var3) {
            throw Exceptions.illegalArgumentException("unable to create message digest:" + var3.getMessage(), var3);
        }
    }

    public TlsDHDomain createDHDomain(TlsDHConfig dhConfig) {
        return new JceTlsDHDomain(this, dhConfig);
    }

    public TlsECDomain createECDomain(TlsECConfig ecConfig) {
        switch(ecConfig.getNamedGroup()) {
            case 29:
                return new JceX25519Domain(this);
            case 30:
                return new JceX448Domain(this);
            default:
                return new JceTlsECDomain(this, ecConfig);
        }
    }

    public TlsSecret hkdfInit(int cryptoHashAlgorithm) {
        return this.adoptLocalSecret(new byte[TlsCryptoUtils.getHashOutputSize(cryptoHashAlgorithm)]);
    }

    protected TlsAEADCipherImpl createAEADCipher(String cipherName, String algorithm, int keySize, boolean isEncrypting) throws GeneralSecurityException {
        return new JceAEADCipherImpl(this.helper, cipherName, algorithm, keySize, isEncrypting);
    }

    protected TlsBlockCipherImpl createBlockCipher(String cipherName, String algorithm, int keySize, boolean isEncrypting) throws GeneralSecurityException {
        return new JceBlockCipherImpl(this.helper.createCipher(cipherName), algorithm, keySize, isEncrypting);
    }

    protected TlsBlockCipherImpl createBlockCipherWithCBCImplicitIV(String cipherName, String algorithm, int keySize, boolean isEncrypting) throws GeneralSecurityException {
        return new JceBlockCipherWithCBCImplicitIVImpl(this.helper.createCipher(cipherName), algorithm, isEncrypting);
    }

    protected TlsHash createHash(String digestName) throws GeneralSecurityException {
        return new JcaTlsHash(this.helper.createDigest(digestName));
    }

    protected TlsNullCipher createNullCipher(TlsCryptoParameters cryptoParams, int macAlgorithm) throws IOException, GeneralSecurityException {
        return new TlsNullCipher(cryptoParams, this.createMAC(cryptoParams, macAlgorithm), this.createMAC(cryptoParams, macAlgorithm));
    }

    protected TlsStreamSigner createStreamSigner(SignatureAndHashAlgorithm algorithm, PrivateKey privateKey, boolean needsRandom) throws IOException {
        String algorithmName = JcaUtils.getJcaAlgorithmName(algorithm);
        return this.createStreamSigner(algorithmName, (AlgorithmParameterSpec)null, privateKey, needsRandom);
    }

    protected TlsStreamSigner createStreamSigner(String algorithmName, AlgorithmParameterSpec parameter, PrivateKey privateKey, boolean needsRandom) throws IOException {
        try {
            Signature signer = this.getHelper().createSignature(algorithmName);
            if (null != parameter) {
                signer.setParameter(parameter);
            }

            signer.initSign(privateKey, needsRandom ? this.getSecureRandom() : null);
            return new JcaTlsStreamSigner(signer);
        } catch (GeneralSecurityException var6) {
            throw new TlsFatalAlert((short)80, var6);
        }
    }

    protected TlsStreamVerifier createStreamVerifier(DigitallySigned signature, PublicKey publicKey) throws IOException {
        String algorithmName = JcaUtils.getJcaAlgorithmName(signature.getAlgorithm());
        return this.createStreamVerifier(algorithmName, (AlgorithmParameterSpec)null, signature.getSignature(), publicKey);
    }

    protected TlsStreamVerifier createStreamVerifier(String algorithmName, AlgorithmParameterSpec parameter, byte[] signature, PublicKey publicKey) throws IOException {
        try {
            Signature verifier = this.getHelper().createSignature(algorithmName);
            if (null != parameter) {
                verifier.setParameter(parameter);
            }

            verifier.initVerify(publicKey);
            return new JcaTlsStreamVerifier(verifier, signature);
        } catch (GeneralSecurityException var6) {
            throw new TlsFatalAlert((short)80, var6);
        }
    }

    protected TlsStreamSigner createVerifyingStreamSigner(SignatureAndHashAlgorithm algorithm, PrivateKey privateKey, boolean needsRandom, PublicKey publicKey) throws IOException {
        String algorithmName = JcaUtils.getJcaAlgorithmName(algorithm);
        return this.createVerifyingStreamSigner(algorithmName, (AlgorithmParameterSpec)null, privateKey, needsRandom, publicKey);
    }

    protected TlsStreamSigner createVerifyingStreamSigner(String algorithmName, AlgorithmParameterSpec parameter, PrivateKey privateKey, boolean needsRandom, PublicKey publicKey) throws IOException {
        try {
            Signature signer = this.getHelper().createSignature(algorithmName);
            Signature verifier = this.getHelper().createSignature(algorithmName);
            if (null != parameter) {
                signer.setParameter(parameter);
                verifier.setParameter(parameter);
            }

            signer.initSign(privateKey, needsRandom ? this.getSecureRandom() : null);
            verifier.initVerify(publicKey);
            return new JcaVerifyingStreamSigner(signer, verifier);
        } catch (GeneralSecurityException var8) {
            throw new TlsFatalAlert((short)80, var8);
        }
    }

    protected Boolean isSupportedEncryptionAlgorithm(int encryptionAlgorithm) {
        switch(encryptionAlgorithm) {
            case 0:
                return Boolean.TRUE;
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
                return Boolean.FALSE;
            case 7:
                return this.isUsableCipher("DESede/CBC/NoPadding", 192);
            case 8:
                return this.isUsableCipher("AES/CBC/NoPadding", 128);
            case 9:
                return this.isUsableCipher("AES/CBC/NoPadding", 256);
            case 10:
                return this.isUsableCipher("AES/GCM/NoPadding", 128);
            case 11:
                return this.isUsableCipher("AES/GCM/NoPadding", 256);
            case 12:
                return this.isUsableCipher("Camellia/CBC/NoPadding", 128);
            case 13:
                return this.isUsableCipher("Camellia/CBC/NoPadding", 256);
            case 14:
                return this.isUsableCipher("SEED/CBC/NoPadding", 128);
            case 15:
            case 16:
                return this.isUsableCipher("AES/CCM/NoPadding", 128);
            case 17:
            case 18:
                return this.isUsableCipher("AES/CCM/NoPadding", 256);
            case 19:
                return this.isUsableCipher("Camellia/GCM/NoPadding", 128);
            case 20:
                return this.isUsableCipher("Camellia/GCM/NoPadding", 256);
            case 21:
                return this.isUsableCipher("ChaCha7539", 256) && this.isUsableMAC("Poly1305");
            case 22:
                return this.isUsableCipher("ARIA/CBC/NoPadding", 128);
            case 23:
                return this.isUsableCipher("ARIA/CBC/NoPadding", 256);
            case 24:
                return this.isUsableCipher("ARIA/GCM/NoPadding", 128);
            case 25:
                return this.isUsableCipher("ARIA/GCM/NoPadding", 256);
            case 26:
                return this.isUsableCipher("SM4/CCM/NoPadding", 128);
            case 27:
                return this.isUsableCipher("SM4/GCM/NoPadding", 128);
            case 28:
                return this.isUsableCipher("SM4/CBC/NoPadding", 128);
            default:
                return null;
        }
    }

    protected Boolean isSupportedNamedGroup(int namedGroup) {
        try {
            if (NamedGroup.refersToAnXDHCurve(namedGroup)) {
                switch(namedGroup) {
                    case 29:
                        this.helper.createKeyAgreement("X25519");
                        return Boolean.TRUE;
                    case 30:
                        this.helper.createKeyAgreement("X448");
                        return Boolean.TRUE;
                }
            } else {
                if (NamedGroup.refersToAnECDSACurve(namedGroup)) {
                    return ECUtil.isCurveSupported(this, NamedGroup.getCurveName(namedGroup));
                }

                if (NamedGroup.refersToASpecificFiniteField(namedGroup)) {
                    return DHUtil.isGroupSupported(this, TlsDHUtils.getNamedDHGroup(namedGroup));
                }
            }

            return null;
        } catch (GeneralSecurityException var3) {
            return Boolean.FALSE;
        }
    }

    protected boolean isUsableCipher(String cipherAlgorithm, int keySize) {
        try {
            this.helper.createCipher(cipherAlgorithm);
            return Cipher.getMaxAllowedKeyLength(cipherAlgorithm) >= keySize;
        } catch (GeneralSecurityException var4) {
            return false;
        }
    }

    protected boolean isUsableMAC(String macAlgorithm) {
        try {
            this.helper.createMac(macAlgorithm);
            return true;
        } catch (GeneralSecurityException var3) {
            return false;
        }
    }

    public JcaJceHelper getHelper() {
        return this.helper;
    }

    protected TlsBlockCipherImpl createCBCBlockCipherImpl(TlsCryptoParameters cryptoParams, String algorithm, int cipherKeySize, boolean forEncryption) throws GeneralSecurityException {
        String cipherName = algorithm + "/CBC/NoPadding";
        return TlsImplUtils.isTLSv11(cryptoParams) ? this.createBlockCipher(cipherName, algorithm, cipherKeySize, forEncryption) : this.createBlockCipherWithCBCImplicitIV(cipherName, algorithm, cipherKeySize, forEncryption);
    }

    private TlsCipher createChaCha20Poly1305(TlsCryptoParameters cryptoParams) throws IOException, GeneralSecurityException {
        return new TlsAEADCipher(cryptoParams, new JceChaCha20Poly1305(this.helper, true), new JceChaCha20Poly1305(this.helper, false), 32, 16, 2);
    }

    private TlsAEADCipher createCipher_AES_CCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize) throws IOException, GeneralSecurityException {
        return new TlsAEADCipher(cryptoParams, this.createAEADCipher("AES/CCM/NoPadding", "AES", cipherKeySize, true), this.createAEADCipher("AES/CCM/NoPadding", "AES", cipherKeySize, false), cipherKeySize, macSize, 1);
    }

    private TlsAEADCipher createCipher_AES_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize) throws IOException, GeneralSecurityException {
        return new TlsAEADCipher(cryptoParams, this.createAEADCipher("AES/GCM/NoPadding", "AES", cipherKeySize, true), this.createAEADCipher("AES/GCM/NoPadding", "AES", cipherKeySize, false), cipherKeySize, macSize, 3);
    }

    private TlsAEADCipher createCipher_ARIA_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize) throws IOException, GeneralSecurityException {
        return new TlsAEADCipher(cryptoParams, this.createAEADCipher("ARIA/GCM/NoPadding", "ARIA", cipherKeySize, true), this.createAEADCipher("ARIA/GCM/NoPadding", "ARIA", cipherKeySize, false), cipherKeySize, macSize, 3);
    }

    private TlsAEADCipher createCipher_Camellia_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize) throws IOException, GeneralSecurityException {
        return new TlsAEADCipher(cryptoParams, this.createAEADCipher("Camellia/GCM/NoPadding", "Camellia", cipherKeySize, true), this.createAEADCipher("Camellia/GCM/NoPadding", "Camellia", cipherKeySize, false), cipherKeySize, macSize, 3);
    }

    protected TlsCipher createCipher_CBC(TlsCryptoParameters cryptoParams, String algorithm, int cipherKeySize, int macAlgorithm) throws GeneralSecurityException, IOException {
        TlsBlockCipherImpl encrypt = this.createCBCBlockCipherImpl(cryptoParams, algorithm, cipherKeySize, true);
        TlsBlockCipherImpl decrypt = this.createCBCBlockCipherImpl(cryptoParams, algorithm, cipherKeySize, false);
        TlsHMAC clientMAC = this.createMAC(cryptoParams, macAlgorithm);
        TlsHMAC serverMAC = this.createMAC(cryptoParams, macAlgorithm);
        return new TlsBlockCipher(cryptoParams, encrypt, decrypt, clientMAC, serverMAC, cipherKeySize);
    }

    private TlsAEADCipher createCipher_SM4_CCM(TlsCryptoParameters cryptoParams) throws IOException, GeneralSecurityException {
        int cipherKeySize = 16;
        int macSize = 16;
        return new TlsAEADCipher(cryptoParams, this.createAEADCipher("SM4/CCM/NoPadding", "SM4", cipherKeySize, true), this.createAEADCipher("SM4/CCM/NoPadding", "SM4", cipherKeySize, false), cipherKeySize, macSize, 1);
    }

    private TlsAEADCipher createCipher_SM4_GCM(TlsCryptoParameters cryptoParams) throws IOException, GeneralSecurityException {
        int cipherKeySize = 16;
        int macSize = 16;
        return new TlsAEADCipher(cryptoParams, this.createAEADCipher("SM4/GCM/NoPadding", "SM4", cipherKeySize, true), this.createAEADCipher("SM4/GCM/NoPadding", "SM4", cipherKeySize, false), cipherKeySize, macSize, 3);
    }

    String getDigestName(int cryptoHashAlgorithm) {
        switch(cryptoHashAlgorithm) {
            case 1:
                return "MD5";
            case 2:
                return "SHA-1";
            case 3:
                return "SHA-224";
            case 4:
                return "SHA-256";
            case 5:
                return "SHA-384";
            case 6:
                return "SHA-512";
            case 7:
                return "SM3";
            default:
                throw new IllegalArgumentException("invalid CryptoHashAlgorithm: " + cryptoHashAlgorithm);
        }
    }
}
