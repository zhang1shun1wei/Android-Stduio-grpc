package com.mi.car.jsse.easysec.pqc.crypto.newhope;

import com.mi.car.jsse.easysec.crypto.engines.ChaChaEngine;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;

class ChaCha20 {
    ChaCha20() {
    }

    static void process(byte[] key, byte[] nonce, byte[] buf, int off, int len) {
        ChaChaEngine e = new ChaChaEngine(20);
        e.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        e.processBytes(buf, off, len, buf, off);
    }
}
