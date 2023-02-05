package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;

public class BasicTlsSRPIdentity implements TlsSRPIdentity {
    protected byte[] identity;
    protected byte[] password;

    public BasicTlsSRPIdentity(byte[] identity2, byte[] password2) {
        this.identity = Arrays.clone(identity2);
        this.password = Arrays.clone(password2);
    }

    public BasicTlsSRPIdentity(String identity2, String password2) {
        this.identity = Strings.toUTF8ByteArray(identity2);
        this.password = Strings.toUTF8ByteArray(password2);
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsSRPIdentity
    public byte[] getSRPIdentity() {
        return this.identity;
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsSRPIdentity
    public byte[] getSRPPassword() {
        return this.password;
    }
}
