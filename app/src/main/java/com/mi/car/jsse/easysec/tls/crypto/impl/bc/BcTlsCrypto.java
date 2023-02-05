package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.agreement.srp.SRP6Client;
import com.mi.car.jsse.easysec.crypto.agreement.srp.SRP6Server;
import com.mi.car.jsse.easysec.crypto.agreement.srp.SRP6VerifierGenerator;
import com.mi.car.jsse.easysec.crypto.digests.MD5Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA1Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA224Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA256Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA384Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import com.mi.car.jsse.easysec.crypto.digests.SM3Digest;
import com.mi.car.jsse.easysec.crypto.engines.AESEngine;
import com.mi.car.jsse.easysec.crypto.engines.ARIAEngine;
import com.mi.car.jsse.easysec.crypto.engines.CamelliaEngine;
import com.mi.car.jsse.easysec.crypto.engines.DESedeEngine;
import com.mi.car.jsse.easysec.crypto.engines.SEEDEngine;
import com.mi.car.jsse.easysec.crypto.engines.SM4Engine;
import com.mi.car.jsse.easysec.crypto.macs.HMac;
import com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.CBCBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.CCMBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.GCMBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.SRP6GroupParameters;
import com.mi.car.jsse.easysec.crypto.prng.DigestRandomGenerator;
import com.mi.car.jsse.easysec.tls.NamedGroup;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.SignatureAndHashAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureScheme;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsCertificate;
import com.mi.car.jsse.easysec.tls.crypto.TlsCipher;
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
import com.mi.car.jsse.easysec.tls.crypto.impl.AbstractTlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsAEADCipher;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsBlockCipher;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsImplUtils;
import com.mi.car.jsse.easysec.tls.crypto.impl.TlsNullCipher;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class BcTlsCrypto extends AbstractTlsCrypto {
    private final SecureRandom entropySource;

    public BcTlsCrypto(SecureRandom entropySource2) {
        this.entropySource = entropySource2;
    }

    /* access modifiers changed from: package-private */
    public BcTlsSecret adoptLocalSecret(byte[] data) {
        return new BcTlsSecret(this, data);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public SecureRandom getSecureRandom() {
        return this.entropySource;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsCertificate createCertificate(byte[] encoding) throws IOException {
        return new BcTlsCertificate(this, encoding);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm) throws IOException {
        switch (encryptionAlgorithm) {
            case 0:
                return createNullCipher(cryptoParams, macAlgorithm);
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            default:
                throw new TlsFatalAlert((short) 80);
            case 7:
                return createCipher_CBC(cryptoParams, encryptionAlgorithm, 24, macAlgorithm);
            case 8:
            case 12:
            case 14:
            case 22:
            case 28:
                return createCipher_CBC(cryptoParams, encryptionAlgorithm, 16, macAlgorithm);
            case 9:
            case 13:
            case 23:
                return createCipher_CBC(cryptoParams, encryptionAlgorithm, 32, macAlgorithm);
            case 10:
                return createCipher_AES_GCM(cryptoParams, 16, 16);
            case 11:
                return createCipher_AES_GCM(cryptoParams, 32, 16);
            case 15:
                return createCipher_AES_CCM(cryptoParams, 16, 16);
            case 16:
                return createCipher_AES_CCM(cryptoParams, 16, 8);
            case 17:
                return createCipher_AES_CCM(cryptoParams, 32, 16);
            case 18:
                return createCipher_AES_CCM(cryptoParams, 32, 8);
            case 19:
                return createCipher_Camellia_GCM(cryptoParams, 16, 16);
            case 20:
                return createCipher_Camellia_GCM(cryptoParams, 32, 16);
            case 21:
                return createChaCha20Poly1305(cryptoParams);
            case 24:
                return createCipher_ARIA_GCM(cryptoParams, 16, 16);
            case 25:
                return createCipher_ARIA_GCM(cryptoParams, 32, 16);
            case 26:
                return createCipher_SM4_CCM(cryptoParams);
            case 27:
                return createCipher_SM4_GCM(cryptoParams);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsDHDomain createDHDomain(TlsDHConfig dhConfig) {
        return new BcTlsDHDomain(this, dhConfig);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsECDomain createECDomain(TlsECConfig ecConfig) {
        switch (ecConfig.getNamedGroup()) {
            case NamedGroup.x25519:
                return new BcX25519Domain(this);
            case NamedGroup.x448:
                return new BcX448Domain(this);
            default:
                return new BcTlsECDomain(this, ecConfig);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsNonceGenerator createNonceGenerator(byte[] additionalSeedMaterial) {
        Digest digest = createDigest(4);
        byte[] seed = new byte[TlsCryptoUtils.getHashOutputSize(4)];
        getSecureRandom().nextBytes(seed);
        DigestRandomGenerator nonceGen = new DigestRandomGenerator(digest);
        nonceGen.addSeedMaterial(additionalSeedMaterial);
        nonceGen.addSeedMaterial(seed);
        return new BcTlsNonceGenerator(nonceGen);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public boolean hasAllRawSignatureAlgorithms() {
        return !hasSignatureAlgorithm((short) 7) && !hasSignatureAlgorithm((short) 8);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public boolean hasDHAgreement() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public boolean hasECDHAgreement() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public boolean hasEncryptionAlgorithm(int encryptionAlgorithm) {
        switch (encryptionAlgorithm) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
                return false;
            default:
                return true;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public boolean hasCryptoHashAlgorithm(int cryptoHashAlgorithm) {
        switch (cryptoHashAlgorithm) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
                return true;
            default:
                return false;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public boolean hasCryptoSignatureAlgorithm(int cryptoSignatureAlgorithm) {
        switch (cryptoSignatureAlgorithm) {
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
            default:
                return false;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public boolean hasMacAlgorithm(int macAlgorithm) {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public boolean hasNamedGroup(int namedGroup) {
        return NamedGroup.refersToASpecificGroup(namedGroup);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public boolean hasRSAEncryption() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public boolean hasSignatureAlgorithm(short signatureAlgorithm) {
        switch (signatureAlgorithm) {
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
            default:
                return false;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public boolean hasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm) {
        short signature = sigAndHashAlgorithm.getSignature();
        switch (sigAndHashAlgorithm.getHash()) {
            case 1:
                if (1 != signature || !hasSignatureAlgorithm(signature)) {
                    return false;
                }
                return true;
            default:
                return hasSignatureAlgorithm(signature);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public boolean hasSignatureScheme(int signatureScheme) {
        boolean z = true;
        switch (signatureScheme) {
            case SignatureScheme.sm2sig_sm3:
                return false;
            default:
                short signature = SignatureScheme.getSignatureAlgorithm(signatureScheme);
                switch (SignatureScheme.getCryptoHashAlgorithm(signatureScheme)) {
                    case 1:
                        if (1 != signature || !hasSignatureAlgorithm(signature)) {
                            z = false;
                        }
                        return z;
                    default:
                        return hasSignatureAlgorithm(signature);
                }
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public boolean hasSRPAuthentication() {
        return true;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsSecret createSecret(byte[] data) {
        return adoptLocalSecret(Arrays.clone(data));
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsSecret generateRSAPreMasterSecret(ProtocolVersion version) {
        byte[] data = new byte[48];
        getSecureRandom().nextBytes(data);
        TlsUtils.writeVersion(version, data, 0);
        return adoptLocalSecret(data);
    }

    public Digest cloneDigest(int cryptoHashAlgorithm, Digest digest) {
        switch (cryptoHashAlgorithm) {
            case 1:
                return new MD5Digest((MD5Digest) digest);
            case 2:
                return new SHA1Digest((SHA1Digest) digest);
            case 3:
                return new SHA224Digest((SHA224Digest) digest);
            case 4:
                return new SHA256Digest((SHA256Digest) digest);
            case 5:
                return new SHA384Digest((SHA384Digest) digest);
            case 6:
                return new SHA512Digest((SHA512Digest) digest);
            case 7:
                return new SM3Digest((SM3Digest) digest);
            default:
                throw new IllegalArgumentException("invalid CryptoHashAlgorithm: " + cryptoHashAlgorithm);
        }
    }

    public Digest createDigest(int cryptoHashAlgorithm) {
        switch (cryptoHashAlgorithm) {
            case 1:
                return new MD5Digest();
            case 2:
                return new SHA1Digest();
            case 3:
                return new SHA224Digest();
            case 4:
                return new SHA256Digest();
            case 5:
                return new SHA384Digest();
            case 6:
                return new SHA512Digest();
            case 7:
                return new SM3Digest();
            default:
                throw new IllegalArgumentException("invalid CryptoHashAlgorithm: " + cryptoHashAlgorithm);
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsHash createHash(int cryptoHashAlgorithm) {
        return new BcTlsHash(this, cryptoHashAlgorithm);
    }

    /* access modifiers changed from: protected */
    public BlockCipher createBlockCipher(int encryptionAlgorithm) throws IOException {
        switch (encryptionAlgorithm) {
            case 7:
                return createDESedeEngine();
            case 8:
            case 9:
                return createAESEngine();
            case 12:
            case 13:
                return createCamelliaEngine();
            case 14:
                return createSEEDEngine();
            case 22:
            case 23:
                return createARIAEngine();
            case 28:
                return createSM4Engine();
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    /* access modifiers changed from: protected */
    public BlockCipher createCBCBlockCipher(BlockCipher blockCipher) {
        return new CBCBlockCipher(blockCipher);
    }

    /* access modifiers changed from: protected */
    public BlockCipher createCBCBlockCipher(int encryptionAlgorithm) throws IOException {
        return createCBCBlockCipher(createBlockCipher(encryptionAlgorithm));
    }

    /* access modifiers changed from: protected */
    public TlsCipher createChaCha20Poly1305(TlsCryptoParameters cryptoParams) throws IOException {
        return new TlsAEADCipher(cryptoParams, new BcChaCha20Poly1305(true), new BcChaCha20Poly1305(false), 32, 16, 2);
    }

    /* access modifiers changed from: protected */
    public TlsAEADCipher createCipher_AES_CCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize) throws IOException {
        return new TlsAEADCipher(cryptoParams, new BcTlsAEADCipherImpl(createAEADBlockCipher_AES_CCM(), true), new BcTlsAEADCipherImpl(createAEADBlockCipher_AES_CCM(), false), cipherKeySize, macSize, 1);
    }

    /* access modifiers changed from: protected */
    public TlsAEADCipher createCipher_AES_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize) throws IOException {
        return new TlsAEADCipher(cryptoParams, new BcTlsAEADCipherImpl(createAEADBlockCipher_AES_GCM(), true), new BcTlsAEADCipherImpl(createAEADBlockCipher_AES_GCM(), false), cipherKeySize, macSize, 3);
    }

    /* access modifiers changed from: protected */
    public TlsAEADCipher createCipher_ARIA_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize) throws IOException {
        return new TlsAEADCipher(cryptoParams, new BcTlsAEADCipherImpl(createAEADBlockCipher_ARIA_GCM(), true), new BcTlsAEADCipherImpl(createAEADBlockCipher_ARIA_GCM(), false), cipherKeySize, macSize, 3);
    }

    /* access modifiers changed from: protected */
    public TlsAEADCipher createCipher_Camellia_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize) throws IOException {
        return new TlsAEADCipher(cryptoParams, new BcTlsAEADCipherImpl(createAEADBlockCipher_Camellia_GCM(), true), new BcTlsAEADCipherImpl(createAEADBlockCipher_Camellia_GCM(), false), cipherKeySize, macSize, 3);
    }

    /* access modifiers changed from: protected */
    public TlsCipher createCipher_CBC(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int cipherKeySize, int macAlgorithm) throws IOException {
        return new TlsBlockCipher(cryptoParams, new BcTlsBlockCipherImpl(createCBCBlockCipher(encryptionAlgorithm), true), new BcTlsBlockCipherImpl(createCBCBlockCipher(encryptionAlgorithm), false), createMAC(cryptoParams, macAlgorithm), createMAC(cryptoParams, macAlgorithm), cipherKeySize);
    }

    /* access modifiers changed from: protected */
    public TlsAEADCipher createCipher_SM4_CCM(TlsCryptoParameters cryptoParams) throws IOException {
        return new TlsAEADCipher(cryptoParams, new BcTlsAEADCipherImpl(createAEADBlockCipher_SM4_CCM(), true), new BcTlsAEADCipherImpl(createAEADBlockCipher_SM4_CCM(), false), 16, 16, 1);
    }

    /* access modifiers changed from: protected */
    public TlsAEADCipher createCipher_SM4_GCM(TlsCryptoParameters cryptoParams) throws IOException {
        return new TlsAEADCipher(cryptoParams, new BcTlsAEADCipherImpl(createAEADBlockCipher_SM4_GCM(), true), new BcTlsAEADCipherImpl(createAEADBlockCipher_SM4_GCM(), false), 16, 16, 3);
    }

    /* access modifiers changed from: protected */
    public TlsNullCipher createNullCipher(TlsCryptoParameters cryptoParams, int macAlgorithm) throws IOException {
        return new TlsNullCipher(cryptoParams, createMAC(cryptoParams, macAlgorithm), createMAC(cryptoParams, macAlgorithm));
    }

    /* access modifiers changed from: protected */
    public BlockCipher createAESEngine() {
        return new AESEngine();
    }

    /* access modifiers changed from: protected */
    public BlockCipher createARIAEngine() {
        return new ARIAEngine();
    }

    /* access modifiers changed from: protected */
    public BlockCipher createCamelliaEngine() {
        return new CamelliaEngine();
    }

    /* access modifiers changed from: protected */
    public BlockCipher createDESedeEngine() {
        return new DESedeEngine();
    }

    /* access modifiers changed from: protected */
    public BlockCipher createSEEDEngine() {
        return new SEEDEngine();
    }

    /* access modifiers changed from: protected */
    public BlockCipher createSM4Engine() {
        return new SM4Engine();
    }

    /* access modifiers changed from: protected */
    public AEADBlockCipher createCCMMode(BlockCipher engine) {
        return new CCMBlockCipher(engine);
    }

    /* access modifiers changed from: protected */
    public AEADBlockCipher createGCMMode(BlockCipher engine) {
        return new GCMBlockCipher(engine);
    }

    /* access modifiers changed from: protected */
    public AEADBlockCipher createAEADBlockCipher_AES_CCM() {
        return createCCMMode(createAESEngine());
    }

    /* access modifiers changed from: protected */
    public AEADBlockCipher createAEADBlockCipher_AES_GCM() {
        return createGCMMode(createAESEngine());
    }

    /* access modifiers changed from: protected */
    public AEADBlockCipher createAEADBlockCipher_ARIA_GCM() {
        return createGCMMode(createARIAEngine());
    }

    /* access modifiers changed from: protected */
    public AEADBlockCipher createAEADBlockCipher_Camellia_GCM() {
        return createGCMMode(createCamelliaEngine());
    }

    /* access modifiers changed from: protected */
    public AEADBlockCipher createAEADBlockCipher_SM4_CCM() {
        return createCCMMode(createSM4Engine());
    }

    /* access modifiers changed from: protected */
    public AEADBlockCipher createAEADBlockCipher_SM4_GCM() {
        return createGCMMode(createSM4Engine());
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsHMAC createHMAC(int macAlgorithm) {
        return createHMACForHash(TlsCryptoUtils.getHashForHMAC(macAlgorithm));
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsHMAC createHMACForHash(int cryptoHashAlgorithm) {
        return new BcTlsHMAC(new HMac(createDigest(cryptoHashAlgorithm)));
    }

    /* access modifiers changed from: protected */
    public TlsHMAC createHMAC_SSL(int macAlgorithm) throws IOException {
        switch (macAlgorithm) {
            case 1:
                return new BcSSL3HMAC(createDigest(1));
            case 2:
                return new BcSSL3HMAC(createDigest(2));
            case 3:
                return new BcSSL3HMAC(createDigest(4));
            case 4:
                return new BcSSL3HMAC(createDigest(5));
            case 5:
                return new BcSSL3HMAC(createDigest(6));
            default:
                throw new TlsFatalAlert((short) 80);
        }
    }

    /* access modifiers changed from: protected */
    public TlsHMAC createMAC(TlsCryptoParameters cryptoParams, int macAlgorithm) throws IOException {
        if (TlsImplUtils.isSSL(cryptoParams)) {
            return createHMAC_SSL(macAlgorithm);
        }
        return createHMAC(macAlgorithm);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsSRP6Client createSRP6Client(TlsSRPConfig srpConfig) {
        BigInteger[] ng = srpConfig.getExplicitNG();
        SRP6GroupParameters srpGroup = new SRP6GroupParameters(ng[0], ng[1]);
        SRP6Client srp6Client = new SRP6Client();
        srp6Client.init(srpGroup, createDigest(2), getSecureRandom());
        return new BcTlsSRP6Client(srp6Client);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsSRP6Server createSRP6Server(TlsSRPConfig srpConfig, BigInteger srpVerifier) {
        BigInteger[] ng = srpConfig.getExplicitNG();
        SRP6GroupParameters srpGroup = new SRP6GroupParameters(ng[0], ng[1]);
        SRP6Server srp6Server = new SRP6Server();
        srp6Server.init(srpGroup, srpVerifier, createDigest(2), getSecureRandom());
        return new BcTlsSRP6Server(srp6Server);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsSRP6VerifierGenerator createSRP6VerifierGenerator(TlsSRPConfig srpConfig) {
        BigInteger[] ng = srpConfig.getExplicitNG();
        SRP6VerifierGenerator srp6VerifierGenerator = new SRP6VerifierGenerator();
        srp6VerifierGenerator.init(ng[0], ng[1], createDigest(2));
        return new BcTlsSRP6VerifierGenerator(srp6VerifierGenerator);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCrypto
    public TlsSecret hkdfInit(int cryptoHashAlgorithm) {
        return adoptLocalSecret(new byte[TlsCryptoUtils.getHashOutputSize(cryptoHashAlgorithm)]);
    }
}
