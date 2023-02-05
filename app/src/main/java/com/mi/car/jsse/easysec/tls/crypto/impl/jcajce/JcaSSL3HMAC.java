package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsHMAC;
import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import com.mi.car.jsse.easysec.util.Arrays;

/* access modifiers changed from: package-private */
public class JcaSSL3HMAC implements TlsHMAC {
    private static final byte IPAD_BYTE = 54;
    private static final byte OPAD_BYTE = 92;
    private static final byte[] IPAD = genPad(IPAD_BYTE, 48);
    private static final byte[] OPAD = genPad(OPAD_BYTE, 48);
    private TlsHash digest;
    private final int digestSize;
    private final int internalBlockSize;
    private int padLength;
    private byte[] secret;

    JcaSSL3HMAC(TlsHash digest2, int digestSize2, int internalBlockSize2) {
        this.digest = digest2;
        this.digestSize = digestSize2;
        this.internalBlockSize = internalBlockSize2;
        if (digestSize2 == 20) {
            this.padLength = 40;
        } else {
            this.padLength = 48;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsMAC
    public void setKey(byte[] key, int keyOff, int keyLen) {
        this.secret = TlsUtils.copyOfRangeExact(key, keyOff, keyOff + keyLen);
        reset();
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsMAC
    public void update(byte[] in, int inOff, int len) {
        this.digest.update(in, inOff, len);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsMAC
    public byte[] calculateMAC() {
        byte[] tmp = this.digest.calculateHash();
        this.digest.update(this.secret, 0, this.secret.length);
        this.digest.update(OPAD, 0, this.padLength);
        this.digest.update(tmp, 0, tmp.length);
        byte[] result = this.digest.calculateHash();
        reset();
        return result;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsMAC
    public void calculateMAC(byte[] output, int outOff) {
        byte[] result = calculateMAC();
        System.arraycopy(result, 0, output, outOff, result.length);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsHMAC
    public int getInternalBlockSize() {
        return this.internalBlockSize;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsMAC
    public int getMacLength() {
        return this.digestSize;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsMAC
    public void reset() {
        this.digest.reset();
        this.digest.update(this.secret, 0, this.secret.length);
        this.digest.update(IPAD, 0, this.padLength);
    }

    private static byte[] genPad(byte b, int count) {
        byte[] padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }
}
