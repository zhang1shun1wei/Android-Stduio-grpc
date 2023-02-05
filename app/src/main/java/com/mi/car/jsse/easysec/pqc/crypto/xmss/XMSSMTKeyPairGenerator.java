package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.OTSHashAddress;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import java.security.SecureRandom;

public final class XMSSMTKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private XMSSMTParameters params;
    private SecureRandom prng;
    private XMSSParameters xmssParams;

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param) {
        XMSSMTKeyGenerationParameters parameters = (XMSSMTKeyGenerationParameters) param;
        this.prng = parameters.getRandom();
        this.params = parameters.getParameters();
        this.xmssParams = this.params.getXMSSParameters();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        XMSSMTPrivateKeyParameters privateKey = generatePrivateKey(new XMSSMTPrivateKeyParameters.Builder(this.params).build().getBDSState());
        this.xmssParams.getWOTSPlus().importKeys(new byte[this.params.getTreeDigestSize()], privateKey.getPublicSeed());
        int rootLayerIndex = this.params.getLayers() - 1;
        BDS bdsRoot = new BDS(this.xmssParams, privateKey.getPublicSeed(), privateKey.getSecretKeySeed(), (OTSHashAddress) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withLayerAddress(rootLayerIndex)).build());
        XMSSNode root = bdsRoot.getRoot();
        privateKey.getBDSState().put(rootLayerIndex, bdsRoot);
        XMSSMTPrivateKeyParameters privateKey2 = new XMSSMTPrivateKeyParameters.Builder(this.params).withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF()).withPublicSeed(privateKey.getPublicSeed()).withRoot(root.getValue()).withBDSState(privateKey.getBDSState()).build();
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new XMSSMTPublicKeyParameters.Builder(this.params).withRoot(root.getValue()).withPublicSeed(privateKey2.getPublicSeed()).build(), (AsymmetricKeyParameter) privateKey2);
    }

    private XMSSMTPrivateKeyParameters generatePrivateKey(BDSStateMap bdsState) {
        int n = this.params.getTreeDigestSize();
        byte[] secretKeySeed = new byte[n];
        this.prng.nextBytes(secretKeySeed);
        byte[] secretKeyPRF = new byte[n];
        this.prng.nextBytes(secretKeyPRF);
        byte[] publicSeed = new byte[n];
        this.prng.nextBytes(publicSeed);
        return new XMSSMTPrivateKeyParameters.Builder(this.params).withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed).withBDSState(bdsState).build();
    }
}
