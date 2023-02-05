package com.mi.car.jsse.easysec.crypto;

public class EphemeralKeyPair {
    private AsymmetricCipherKeyPair keyPair;
    private KeyEncoder publicKeyEncoder;

    public EphemeralKeyPair(AsymmetricCipherKeyPair keyPair2, KeyEncoder publicKeyEncoder2) {
        this.keyPair = keyPair2;
        this.publicKeyEncoder = publicKeyEncoder2;
    }

    public AsymmetricCipherKeyPair getKeyPair() {
        return this.keyPair;
    }

    public byte[] getEncodedPublicKey() {
        return this.publicKeyEncoder.getEncoded(this.keyPair.getPublic());
    }
}
