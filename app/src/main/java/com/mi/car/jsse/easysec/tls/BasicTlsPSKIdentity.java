package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;

public class BasicTlsPSKIdentity implements TlsPSKIdentity {
    protected byte[] identity;
    protected byte[] psk;

    public BasicTlsPSKIdentity(byte[] identity2, byte[] psk2) {
        this.identity = Arrays.clone(identity2);
        this.psk = Arrays.clone(psk2);
    }

    public BasicTlsPSKIdentity(String identity2, byte[] psk2) {
        this.identity = Strings.toUTF8ByteArray(identity2);
        this.psk = Arrays.clone(psk2);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPSKIdentity
    public void skipIdentityHint() {
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPSKIdentity
    public void notifyIdentityHint(byte[] psk_identity_hint) {
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPSKIdentity
    public byte[] getPSKIdentity() {
        return this.identity;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsPSKIdentity
    public byte[] getPSK() {
        return Arrays.clone(this.psk);
    }
}
