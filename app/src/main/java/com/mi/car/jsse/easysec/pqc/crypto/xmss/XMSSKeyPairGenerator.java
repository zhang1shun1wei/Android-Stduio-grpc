package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.OTSHashAddress;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSPublicKeyParameters;
import java.security.SecureRandom;

public final class XMSSKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private XMSSParameters params;
    private SecureRandom prng;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param) {
        XMSSKeyGenerationParameters parameters = (XMSSKeyGenerationParameters) param;
        this.prng = parameters.getRandom();
        this.params = parameters.getParameters();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        XMSSPrivateKeyParameters privateKey = generatePrivateKey(this.params, this.prng);
        XMSSNode root = privateKey.getBDSState().getRoot();
        XMSSPrivateKeyParameters privateKey2 = new XMSSPrivateKeyParameters.Builder(this.params).withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF()).withPublicSeed(privateKey.getPublicSeed()).withRoot(root.getValue()).withBDSState(privateKey.getBDSState()).build();
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new XMSSPublicKeyParameters.Builder(this.params).withRoot(root.getValue()).withPublicSeed(privateKey2.getPublicSeed()).build(), (AsymmetricKeyParameter) privateKey2);
    }

    private XMSSPrivateKeyParameters generatePrivateKey(XMSSParameters params2, SecureRandom prng2) {
        int n = params2.getTreeDigestSize();
        byte[] secretKeySeed = new byte[n];
        prng2.nextBytes(secretKeySeed);
        byte[] secretKeyPRF = new byte[n];
        prng2.nextBytes(secretKeyPRF);
        byte[] publicSeed = new byte[n];
        prng2.nextBytes(publicSeed);
        return new XMSSPrivateKeyParameters.Builder(params2).withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed).withBDSState(new BDS(params2, publicSeed, secretKeySeed, (OTSHashAddress) new OTSHashAddress.Builder().build())).build();
    }
}
