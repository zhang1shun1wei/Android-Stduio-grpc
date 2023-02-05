package com.mi.car.jsse.easysec.tls;

public interface TlsPSKIdentityManager {
    byte[] getHint();

    byte[] getPSK(byte[] bArr);
}
