package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;
import java.text.ParseException;

public final class XMSSMT {
    private XMSSMTParameters params;
    private XMSSMTPrivateKeyParameters privateKey;
    private SecureRandom prng;
    private XMSSMTPublicKeyParameters publicKey;
    private XMSSParameters xmssParams;

    public XMSSMT(XMSSMTParameters params2, SecureRandom prng2) {
        if (params2 == null) {
            throw new NullPointerException("params == null");
        }
        this.params = params2;
        this.xmssParams = params2.getXMSSParameters();
        this.prng = prng2;
        this.privateKey = new XMSSMTPrivateKeyParameters.Builder(params2).build();
        this.publicKey = new XMSSMTPublicKeyParameters.Builder(params2).build();
    }

    public void generateKeys() {
        XMSSMTKeyPairGenerator kpGen = new XMSSMTKeyPairGenerator();
        kpGen.init(new XMSSMTKeyGenerationParameters(getParams(), this.prng));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        this.privateKey = (XMSSMTPrivateKeyParameters) kp.getPrivate();
        this.publicKey = (XMSSMTPublicKeyParameters) kp.getPublic();
        importState(this.privateKey, this.publicKey);
    }

    private void importState(XMSSMTPrivateKeyParameters privateKey2, XMSSMTPublicKeyParameters publicKey2) {
        this.xmssParams.getWOTSPlus().importKeys(new byte[this.params.getTreeDigestSize()], this.privateKey.getPublicSeed());
        this.privateKey = privateKey2;
        this.publicKey = publicKey2;
    }

    public void importState(byte[] privateKey2, byte[] publicKey2) {
        if (privateKey2 == null) {
            throw new NullPointerException("privateKey == null");
        } else if (publicKey2 == null) {
            throw new NullPointerException("publicKey == null");
        } else {
            XMSSMTPrivateKeyParameters xmssMTPrivateKey = new XMSSMTPrivateKeyParameters.Builder(this.params).withPrivateKey(privateKey2).build();
            XMSSMTPublicKeyParameters xmssMTPublicKey = new XMSSMTPublicKeyParameters.Builder(this.params).withPublicKey(publicKey2).build();
            if (!Arrays.areEqual(xmssMTPrivateKey.getRoot(), xmssMTPublicKey.getRoot())) {
                throw new IllegalStateException("root of private key and public key do not match");
            } else if (!Arrays.areEqual(xmssMTPrivateKey.getPublicSeed(), xmssMTPublicKey.getPublicSeed())) {
                throw new IllegalStateException("public seed of private key and public key do not match");
            } else {
                this.xmssParams.getWOTSPlus().importKeys(new byte[this.params.getTreeDigestSize()], xmssMTPrivateKey.getPublicSeed());
                this.privateKey = xmssMTPrivateKey;
                this.publicKey = xmssMTPublicKey;
            }
        }
    }

    public byte[] sign(byte[] message) {
        if (message == null) {
            throw new NullPointerException("message == null");
        }
        XMSSMTSigner signer = new XMSSMTSigner();
        signer.init(true, this.privateKey);
        byte[] signature = signer.generateSignature(message);
        this.privateKey = (XMSSMTPrivateKeyParameters) signer.getUpdatedPrivateKey();
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
            XMSSMTSigner signer = new XMSSMTSigner();
            signer.init(false, new XMSSMTPublicKeyParameters.Builder(getParams()).withPublicKey(publicKey2).build());
            return signer.verifySignature(message, signature);
        }
    }

    public byte[] exportPrivateKey() {
        return this.privateKey.toByteArray();
    }

    public byte[] exportPublicKey() {
        return this.publicKey.toByteArray();
    }

    public XMSSMTParameters getParams() {
        return this.params;
    }

    public byte[] getPublicSeed() {
        return this.privateKey.getPublicSeed();
    }

    /* access modifiers changed from: protected */
    public XMSSParameters getXMSS() {
        return this.xmssParams;
    }
}
