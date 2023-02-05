package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.crypto.macs.HMac;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.tls.crypto.TlsHMAC;

final class BcTlsHMAC implements TlsHMAC {
    private final HMac hmac;

    BcTlsHMAC(HMac hmac) {
        this.hmac = hmac;
    }

    public void setKey(byte[] key, int keyOff, int keyLen) {
        this.hmac.init(new KeyParameter(key, keyOff, keyLen));
    }

    public void update(byte[] input, int inOff, int length) {
        this.hmac.update(input, inOff, length);
    }

    public byte[] calculateMAC() {
        byte[] rv = new byte[this.hmac.getMacSize()];
        this.hmac.doFinal(rv, 0);
        return rv;
    }

    public void calculateMAC(byte[] output, int outOff) {
        this.hmac.doFinal(output, outOff);
    }

    public int getInternalBlockSize() {
        return ((ExtendedDigest)this.hmac.getUnderlyingDigest()).getByteLength();
    }

    public int getMacLength() {
        return this.hmac.getMacSize();
    }

    public void reset() {
        this.hmac.reset();
    }
}
