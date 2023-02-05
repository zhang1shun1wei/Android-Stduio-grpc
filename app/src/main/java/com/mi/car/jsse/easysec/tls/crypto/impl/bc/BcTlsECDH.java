package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.params.ECPrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.ECPublicKeyParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsAgreement;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.IOException;

public class BcTlsECDH implements TlsAgreement {
    protected final BcTlsECDomain domain;
    protected AsymmetricCipherKeyPair localKeyPair;
    protected ECPublicKeyParameters peerPublicKey;

    public BcTlsECDH(BcTlsECDomain domain2) {
        this.domain = domain2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsAgreement
    public byte[] generateEphemeral() throws IOException {
        this.localKeyPair = this.domain.generateKeyPair();
        return this.domain.encodePublicKey((ECPublicKeyParameters) this.localKeyPair.getPublic());
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsAgreement
    public void receivePeerValue(byte[] peerValue) throws IOException {
        this.peerPublicKey = this.domain.decodePublicKey(peerValue);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsAgreement
    public TlsSecret calculateSecret() throws IOException {
        return this.domain.calculateECDHAgreement((ECPrivateKeyParameters) this.localKeyPair.getPrivate(), this.peerPublicKey);
    }
}
