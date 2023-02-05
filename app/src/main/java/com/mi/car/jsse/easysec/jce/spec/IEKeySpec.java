package com.mi.car.jsse.easysec.jce.spec;

import com.mi.car.jsse.easysec.jce.interfaces.IESKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;

public class IEKeySpec implements KeySpec, IESKey {
    private PrivateKey privKey;
    private PublicKey pubKey;

    public IEKeySpec(PrivateKey privKey2, PublicKey pubKey2) {
        this.privKey = privKey2;
        this.pubKey = pubKey2;
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.IESKey
    public PublicKey getPublic() {
        return this.pubKey;
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.IESKey
    public PrivateKey getPrivate() {
        return this.privKey;
    }

    public String getAlgorithm() {
        return "IES";
    }

    public String getFormat() {
        return null;
    }

    public byte[] getEncoded() {
        return null;
    }
}
