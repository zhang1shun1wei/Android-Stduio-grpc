package com.mi.car.jsse.easysec.crypto.prng.drbg;

public interface SP80090DRBG {
    int generate(byte[] bArr, byte[] bArr2, boolean z);

    int getBlockSize();

    void reseed(byte[] bArr);
}
