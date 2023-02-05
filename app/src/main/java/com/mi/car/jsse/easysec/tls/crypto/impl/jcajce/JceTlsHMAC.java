package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsHMAC;
import java.security.InvalidKeyException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

public class JceTlsHMAC implements TlsHMAC {
    private final String algorithm;
    private final Mac hmac;
    private final int internalBlockSize;

    public JceTlsHMAC(int cryptoHashAlgorithm, Mac hmac2, String algorithm2) {
        this.hmac = hmac2;
        this.algorithm = algorithm2;
        this.internalBlockSize = TlsCryptoUtils.getHashInternalSize(cryptoHashAlgorithm);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsMAC
    public void setKey(byte[] key, int keyOff, int keyLen) {
        try {
            this.hmac.init(new SecretKeySpec(key, keyOff, keyLen, this.algorithm));
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsMAC
    public void update(byte[] input, int inOff, int length) {
        this.hmac.update(input, inOff, length);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsMAC
    public byte[] calculateMAC() {
        return this.hmac.doFinal();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsMAC
    public void calculateMAC(byte[] output, int outOff) {
        try {
            this.hmac.doFinal(output, outOff);
        } catch (ShortBufferException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHMAC
    public int getInternalBlockSize() {
        return this.internalBlockSize;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsMAC
    public int getMacLength() {
        return this.hmac.getMacLength();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsMAC
    public void reset() {
        this.hmac.reset();
    }
}
