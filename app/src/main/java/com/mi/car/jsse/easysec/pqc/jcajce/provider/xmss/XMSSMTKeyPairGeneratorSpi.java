package com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.digests.SHA256Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHA512Digest;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTKeyGenerationParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTKeyPairGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.XMSSMTParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class XMSSMTKeyPairGeneratorSpi extends KeyPairGenerator {
    private XMSSMTKeyPairGenerator engine = new XMSSMTKeyPairGenerator();
    private boolean initialised = false;
    private XMSSMTKeyGenerationParameters param;
    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private ASN1ObjectIdentifier treeDigest;

    public XMSSMTKeyPairGeneratorSpi() {
        super("XMSSMT");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int strength, SecureRandom random2) {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec params, SecureRandom random2) throws InvalidAlgorithmParameterException {
        if (!(params instanceof XMSSMTParameterSpec)) {
            throw new InvalidAlgorithmParameterException("parameter object not a XMSSMTParameterSpec");
        }
        XMSSMTParameterSpec xmssParams = (XMSSMTParameterSpec) params;
        if (xmssParams.getTreeDigest().equals("SHA256")) {
            this.treeDigest = NISTObjectIdentifiers.id_sha256;
            this.param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), new SHA256Digest()), random2);
        } else if (xmssParams.getTreeDigest().equals("SHA512")) {
            this.treeDigest = NISTObjectIdentifiers.id_sha512;
            this.param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), new SHA512Digest()), random2);
        } else if (xmssParams.getTreeDigest().equals("SHAKE128")) {
            this.treeDigest = NISTObjectIdentifiers.id_shake128;
            this.param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), new SHAKEDigest(128)), random2);
        } else if (xmssParams.getTreeDigest().equals("SHAKE256")) {
            this.treeDigest = NISTObjectIdentifiers.id_shake256;
            this.param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), new SHAKEDigest(256)), random2);
        }
        this.engine.init(this.param);
        this.initialised = true;
    }

    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(10, 20, new SHA512Digest()), this.random);
            this.engine.init(this.param);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair pair = this.engine.generateKeyPair();
        return new KeyPair(new BCXMSSMTPublicKey(this.treeDigest, (XMSSMTPublicKeyParameters) pair.getPublic()), new BCXMSSMTPrivateKey(this.treeDigest, (XMSSMTPrivateKeyParameters) pair.getPrivate()));
    }
}
