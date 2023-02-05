package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSPublicKeyParameters;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;
import java.text.ParseException;

public class XMSS {
    private final XMSSParameters params;
    private XMSSPrivateKeyParameters privateKey;
    private SecureRandom prng;
    private XMSSPublicKeyParameters publicKey;
    private WOTSPlus wotsPlus;

    public XMSS(XMSSParameters params2, SecureRandom prng2) {
        if (params2 == null) {
            throw new NullPointerException("params == null");
        }
        this.params = params2;
        this.wotsPlus = params2.getWOTSPlus();
        this.prng = prng2;
    }

    public void generateKeys() {
        XMSSKeyPairGenerator kpGen = new XMSSKeyPairGenerator();
        kpGen.init(new XMSSKeyGenerationParameters(getParams(), this.prng));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        this.privateKey = (XMSSPrivateKeyParameters) kp.getPrivate();
        this.publicKey = (XMSSPublicKeyParameters) kp.getPublic();
        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
    }

    public void importState(XMSSPrivateKeyParameters privateKey2, XMSSPublicKeyParameters publicKey2) {
        if (!Arrays.areEqual(privateKey2.getRoot(), publicKey2.getRoot())) {
            throw new IllegalStateException("root of private key and public key do not match");
        } else if (!Arrays.areEqual(privateKey2.getPublicSeed(), publicKey2.getPublicSeed())) {
            throw new IllegalStateException("public seed of private key and public key do not match");
        } else {
            this.privateKey = privateKey2;
            this.publicKey = publicKey2;
            this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
        }
    }

    public void importState(byte[] privateKey2, byte[] publicKey2) {
        if (privateKey2 == null) {
            throw new NullPointerException("privateKey == null");
        } else if (publicKey2 == null) {
            throw new NullPointerException("publicKey == null");
        } else {
            XMSSPrivateKeyParameters tmpPrivateKey = new XMSSPrivateKeyParameters.Builder(this.params).withPrivateKey(privateKey2).build();
            XMSSPublicKeyParameters tmpPublicKey = new XMSSPublicKeyParameters.Builder(this.params).withPublicKey(publicKey2).build();
            if (!Arrays.areEqual(tmpPrivateKey.getRoot(), tmpPublicKey.getRoot())) {
                throw new IllegalStateException("root of private key and public key do not match");
            } else if (!Arrays.areEqual(tmpPrivateKey.getPublicSeed(), tmpPublicKey.getPublicSeed())) {
                throw new IllegalStateException("public seed of private key and public key do not match");
            } else {
                this.privateKey = tmpPrivateKey;
                this.publicKey = tmpPublicKey;
                this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
            }
        }
    }

    public byte[] sign(byte[] message) {
        if (message == null) {
            throw new NullPointerException("message == null");
        }
        XMSSSigner signer = new XMSSSigner();
        signer.init(true, this.privateKey);
        byte[] signature = signer.generateSignature(message);
        this.privateKey = (XMSSPrivateKeyParameters) signer.getUpdatedPrivateKey();
        importState(this.privateKey, this.publicKey);
        return signature;
    }

    public boolean verifySignature(byte[] message, byte[] signature, byte[] publicKey2) throws ParseException {
        if (message == null) {
            throw new NullPointerException("message == null");
        } else if (signature == null) {
            throw new NullPointerException("signature == null");
        } else if (publicKey2 == null) {
            throw new NullPointerException("publicKey == null");
        } else {
            XMSSSigner signer = new XMSSSigner();
            signer.init(false, new XMSSPublicKeyParameters.Builder(getParams()).withPublicKey(publicKey2).build());
            return signer.verifySignature(message, signature);
        }
    }

    public XMSSPrivateKeyParameters exportPrivateKey() {
        return this.privateKey;
    }

    public XMSSPublicKeyParameters exportPublicKey() {
        return this.publicKey;
    }

    /* access modifiers changed from: protected */
    public WOTSPlusSignature wotsSign(byte[] messageDigest, OTSHashAddress otsHashAddress) {
        if (messageDigest.length != this.params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        } else if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        } else {
            this.wotsPlus.importKeys(this.wotsPlus.getWOTSPlusSecretKey(this.privateKey.getSecretKeySeed(), otsHashAddress), getPublicSeed());
            return this.wotsPlus.sign(messageDigest, otsHashAddress);
        }
    }

    public XMSSParameters getParams() {
        return this.params;
    }

    /* access modifiers changed from: protected */
    public WOTSPlus getWOTSPlus() {
        return this.wotsPlus;
    }

    public byte[] getRoot() {
        return this.privateKey.getRoot();
    }

    /* access modifiers changed from: protected */
    public void setRoot(byte[] root) {
        this.privateKey = new XMSSPrivateKeyParameters.Builder(this.params).withSecretKeySeed(this.privateKey.getSecretKeySeed()).withSecretKeyPRF(this.privateKey.getSecretKeyPRF()).withPublicSeed(getPublicSeed()).withRoot(root).withBDSState(this.privateKey.getBDSState()).build();
        this.publicKey = new XMSSPublicKeyParameters.Builder(this.params).withRoot(root).withPublicSeed(getPublicSeed()).build();
    }

    public int getIndex() {
        return this.privateKey.getIndex();
    }

    /* access modifiers changed from: protected */
    public void setIndex(int index) {
        this.privateKey = new XMSSPrivateKeyParameters.Builder(this.params).withSecretKeySeed(this.privateKey.getSecretKeySeed()).withSecretKeyPRF(this.privateKey.getSecretKeyPRF()).withPublicSeed(this.privateKey.getPublicSeed()).withRoot(this.privateKey.getRoot()).withBDSState(this.privateKey.getBDSState()).build();
    }

    public byte[] getPublicSeed() {
        return this.privateKey.getPublicSeed();
    }

    /* access modifiers changed from: protected */
    public void setPublicSeed(byte[] publicSeed) {
        this.privateKey = new XMSSPrivateKeyParameters.Builder(this.params).withSecretKeySeed(this.privateKey.getSecretKeySeed()).withSecretKeyPRF(this.privateKey.getSecretKeyPRF()).withPublicSeed(publicSeed).withRoot(getRoot()).withBDSState(this.privateKey.getBDSState()).build();
        this.publicKey = new XMSSPublicKeyParameters.Builder(this.params).withRoot(getRoot()).withPublicSeed(publicSeed).build();
        this.wotsPlus.importKeys(new byte[this.params.getTreeDigestSize()], publicSeed);
    }

    public XMSSPrivateKeyParameters getPrivateKey() {
        return this.privateKey;
    }
}
