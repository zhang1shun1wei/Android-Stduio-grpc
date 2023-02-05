package com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.digests.SHA256Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSKeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSKeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.XMSSParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class XMSSKeyPairGeneratorSpi extends KeyPairGenerator {
    private XMSSKeyPairGenerator engine = new XMSSKeyPairGenerator();
    private boolean initialised = false;
    private XMSSKeyGenerationParameters param;
    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private ASN1ObjectIdentifier treeDigest;

    public XMSSKeyPairGeneratorSpi() {
        super("XMSS");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int strength, SecureRandom random2) {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random2) throws InvalidAlgorithmParameterException {
        if (!(params instanceof XMSSParameterSpec)) {
            throw new InvalidAlgorithmParameterException("parameter object not a XMSSParameterSpec");
        }
        XMSSParameterSpec xmssParams = (XMSSParameterSpec) params;
        if (xmssParams.getTreeDigest().equals("SHA256")) {
            this.treeDigest = NISTObjectIdentifiers.id_sha256;
            this.param = new XMSSKeyGenerationParameters(new XMSSParameters(xmssParams.getHeight(), new SHA256Digest()), random2);
        } else if (xmssParams.getTreeDigest().equals("SHA512")) {
            this.treeDigest = NISTObjectIdentifiers.id_sha512;
            this.param = new XMSSKeyGenerationParameters(new XMSSParameters(xmssParams.getHeight(), new SHA512Digest()), random2);
        } else if (xmssParams.getTreeDigest().equals("SHAKE128")) {
            this.treeDigest = NISTObjectIdentifiers.id_shake128;
            this.param = new XMSSKeyGenerationParameters(new XMSSParameters(xmssParams.getHeight(), new SHAKEDigest(128)), random2);
        } else if (xmssParams.getTreeDigest().equals("SHAKE256")) {
            this.treeDigest = NISTObjectIdentifiers.id_shake256;
            this.param = new XMSSKeyGenerationParameters(new XMSSParameters(xmssParams.getHeight(), new SHAKEDigest(256)), random2);
        }
        this.engine.init(this.param);
        this.initialised = true;
    }

    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.param = new XMSSKeyGenerationParameters(new XMSSParameters(10, new SHA512Digest()), this.random);
            this.engine.init(this.param);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
        return new KeyPair(new BCXMSSPublicKey(this.treeDigest, (XMSSPublicKeyParameters) pair.getPublic()), new BCXMSSPrivateKey(this.treeDigest, (XMSSPrivateKeyParameters) pair.getPrivate()));
    }
}
