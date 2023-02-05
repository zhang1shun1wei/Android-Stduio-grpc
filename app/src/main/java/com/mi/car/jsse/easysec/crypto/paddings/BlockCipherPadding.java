package com.mi.car.jsse.easysec.crypto.paddings;

import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import java.security.SecureRandom;

public interface BlockCipherPadding {
    int addPadding(byte[] bArr, int i);

    String getPaddingName();

    void init(SecureRandom secureRandom) throws IllegalArgumentException;

    int padCount(byte[] bArr) throws InvalidCipherTextException;
}
