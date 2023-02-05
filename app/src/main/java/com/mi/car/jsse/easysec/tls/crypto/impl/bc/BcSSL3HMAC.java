package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsHMAC;
import com.mi.car.jsse.easysec.util.Arrays;

class BcSSL3HMAC implements TlsHMAC {
    private static final byte IPAD_BYTE = 54;
    private static final byte OPAD_BYTE = 92;
    private static final byte[] IPAD = genPad((byte)54, 48);
    private static final byte[] OPAD = genPad((byte)92, 48);
    private Digest digest;
    private int padLength;
    private byte[] secret;

    BcSSL3HMAC(Digest digest) {
        this.digest = digest;
        if (digest.getDigestSize() == 20) {
            this.padLength = 40;
        } else {
            this.padLength = 48;
        }

    }

    public void setKey(byte[] key, int keyOff, int keyLen) {
        this.secret = TlsUtils.copyOfRangeExact(key, keyOff, keyOff + keyLen);
        this.reset();
    }

    public void update(byte[] in, int inOff, int len) {
        this.digest.update(in, inOff, len);
    }

    public byte[] calculateMAC() {
        byte[] result = new byte[this.digest.getDigestSize()];
        this.doFinal(result, 0);
        return result;
    }

    public void calculateMAC(byte[] output, int outOff) {
        this.doFinal(output, outOff);
    }

    public int getInternalBlockSize() {
        return ((ExtendedDigest)this.digest).getByteLength();
    }

    public int getMacLength() {
        return this.digest.getDigestSize();
    }

    public void reset() {
        this.digest.reset();
        this.digest.update(this.secret, 0, this.secret.length);
        this.digest.update(IPAD, 0, this.padLength);
    }

    private void doFinal(byte[] out, int outOff) {
        byte[] tmp = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(tmp, 0);
        this.digest.update(this.secret, 0, this.secret.length);
        this.digest.update(OPAD, 0, this.padLength);
        this.digest.update(tmp, 0, tmp.length);
        this.digest.doFinal(out, outOff);
        this.reset();
    }

    private static byte[] genPad(byte b, int count) {
        byte[] padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }
}
