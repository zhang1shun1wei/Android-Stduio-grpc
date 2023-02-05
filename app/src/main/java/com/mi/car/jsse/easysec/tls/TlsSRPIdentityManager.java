package com.mi.car.jsse.easysec.tls;

public interface TlsSRPIdentityManager {
    TlsSRPLoginParameters getLoginParameters(byte[] bArr);
}
