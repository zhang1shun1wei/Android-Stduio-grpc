package com.mi.car.jsse.easysec.crypto.macs;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;

public class CMacWithIV extends CMac {
    public CMacWithIV(BlockCipher cipher) {
        super(cipher);
    }

    public CMacWithIV(BlockCipher cipher, int macSizeInBits) {
        super(cipher, macSizeInBits);
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.crypto.macs.CMac
    public void validate(CipherParameters params) {
    }
}
