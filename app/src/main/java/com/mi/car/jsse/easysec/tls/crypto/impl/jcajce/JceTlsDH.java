package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.IOException;
import java.security.KeyPair;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

public class JceTlsDH implements TlsAgreement {
    protected final JceTlsDHDomain domain;
    protected KeyPair localKeyPair;
    protected DHPublicKey peerPublicKey;

    public JceTlsDH(JceTlsDHDomain domain2) {
        this.domain = domain2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsAgreement
    public byte[] generateEphemeral() throws IOException {
        this.localKeyPair = this.domain.generateKeyPair();
        return this.domain.encodePublicKey((DHPublicKey) this.localKeyPair.getPublic());
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsAgreement
    public void receivePeerValue(byte[] peerValue) throws IOException {
        this.peerPublicKey = this.domain.decodePublicKey(peerValue);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsAgreement
    public TlsSecret calculateSecret() throws IOException {
        return this.domain.calculateDHAgreement((DHPrivateKey) this.localKeyPair.getPrivate(), this.peerPublicKey);
    }
}
