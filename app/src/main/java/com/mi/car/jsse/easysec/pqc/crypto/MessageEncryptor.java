package com.mi.car.jsse.easysec.pqc.crypto;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;

public interface MessageEncryptor {
    void init(boolean z, CipherParameters cipherParameters);

    byte[] messageDecrypt(byte[] bArr) throws InvalidCipherTextException;

    byte[] messageEncrypt(byte[] bArr);
}
