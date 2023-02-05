package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;

public interface AEADBlockCipher extends AEADCipher {
    BlockCipher getUnderlyingCipher();
}
