package com.mi.car.jsse.easysec.jcajce.provider.symmetric.util;

import com.mi.car.jsse.easysec.crypto.BlockCipher;

public interface BlockCipherProvider
{
    BlockCipher get();
}
