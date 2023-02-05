package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BasicAgreement;
import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.DerivationFunction;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.util.Pack;

public class OldIESEngine extends IESEngine {
    public OldIESEngine(BasicAgreement agree, DerivationFunction kdf, Mac mac) {
        super(agree, kdf, mac);
    }

    public OldIESEngine(BasicAgreement agree, DerivationFunction kdf, Mac mac, BufferedBlockCipher cipher) {
        super(agree, kdf, mac, cipher);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.crypto.engines.IESEngine
    public byte[] getLengthTag(byte[] p2) {
        byte[] L2 = new byte[4];
        if (p2 != null) {
            Pack.intToBigEndian(p2.length * 8, L2, 0);
        }
        return L2;
    }
}
