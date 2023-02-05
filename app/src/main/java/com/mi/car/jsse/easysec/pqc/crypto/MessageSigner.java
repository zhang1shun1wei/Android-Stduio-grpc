package com.mi.car.jsse.easysec.pqc.crypto;

import com.mi.car.jsse.easysec.crypto.CipherParameters;

public interface MessageSigner {
    byte[] generateSignature(byte[] bArr);

    void init(boolean z, CipherParameters cipherParameters);

    boolean verifySignature(byte[] bArr, byte[] bArr2);
}
