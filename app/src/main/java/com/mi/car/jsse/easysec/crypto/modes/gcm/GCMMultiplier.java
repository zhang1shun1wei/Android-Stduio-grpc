package com.mi.car.jsse.easysec.crypto.modes.gcm;

public interface GCMMultiplier {
    void init(byte[] bArr);

    void multiplyH(byte[] bArr);
}
