package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

import java.io.IOException;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.macs.HMac;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.tls.CipherSuite;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.tls.crypto.impl.AbstractTlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.impl.AbstractTlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;

public class BcTlsSecret extends AbstractTlsSecret {
    private static final byte[] SSL3_CONST = generateSSL3Constants();
    protected final BcTlsCrypto crypto;

    public static BcTlsSecret convert(BcTlsCrypto crypto2, TlsSecret secret) {
        if (secret instanceof BcTlsSecret) {
            return (BcTlsSecret) secret;
        }
        if (secret instanceof AbstractTlsSecret) {
            return crypto2.adoptLocalSecret(copyData((AbstractTlsSecret) secret));
        }
        throw new IllegalArgumentException("unrecognized TlsSecret - cannot copy data: " + secret.getClass().getName());
    }

    private static byte[] generateSSL3Constants() {
        byte[] result = new byte[120];
        int pos = 0;
        int i = 0;
        while (i < 15) {
            byte b = (byte) (i + 65);
            int j = 0;
            int pos2 = pos;
            while (j <= i) {
                result[pos2] = b;
                j++;
                pos2++;
            }
            i++;
            pos = pos2;
        }
        return result;
    }

    public BcTlsSecret(BcTlsCrypto crypto2, byte[] data) {
        super(data);
        this.crypto = crypto2;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSecret
    public synchronized TlsSecret deriveUsingPRF(int prfAlgorithm, String label, byte[] seed, int length) throws IOException {
        TlsSecret hkdfExpandLabel;
        checkAlive();
        switch (prfAlgorithm) {
            case 4:
                hkdfExpandLabel = TlsCryptoUtils.hkdfExpandLabel(this, 4, label, seed, length);
                break;
            case 5:
                hkdfExpandLabel = TlsCryptoUtils.hkdfExpandLabel(this, 5, label, seed, length);
                break;
            case 6:
            default:
                try {
                    hkdfExpandLabel = this.crypto.adoptLocalSecret(prf(prfAlgorithm, label, seed, length));
                    break;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            case 7:
                hkdfExpandLabel = TlsCryptoUtils.hkdfExpandLabel(this, 7, label, seed, length);
                break;
        }
        return hkdfExpandLabel;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSecret
    public synchronized TlsSecret hkdfExpand(int cryptoHashAlgorithm, byte[] info, int length) {
        int remaining;
        BcTlsSecret adoptLocalSecret;
        if (length < 1) {
            adoptLocalSecret = this.crypto.adoptLocalSecret(TlsUtils.EMPTY_BYTES);
        } else {
            int hashLen = TlsCryptoUtils.getHashOutputSize(cryptoHashAlgorithm);
            if (length > hashLen * CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
                throw new IllegalArgumentException("'length' must be <= 255 * (output size of 'hashAlgorithm')");
            }
            checkAlive();
            byte[] prk = this.data;
            HMac hmac = new HMac(this.crypto.createDigest(cryptoHashAlgorithm));
            hmac.init(new KeyParameter(prk));
            byte[] okm = new byte[length];
            byte[] t = new byte[hashLen];
            byte counter = 0;
            int pos = 0;
            while (true) {
                hmac.update(info, 0, info.length);
                counter = (byte) (counter + 1);
                hmac.update(counter);
                hmac.doFinal(t, 0);
                remaining = length - pos;
                if (remaining <= hashLen) {
                    break;
                }
                System.arraycopy(t, 0, okm, pos, hashLen);
                pos += hashLen;
                hmac.update(t, 0, t.length);
            }
            System.arraycopy(t, 0, okm, pos, remaining);
            adoptLocalSecret = this.crypto.adoptLocalSecret(okm);
        }
        return adoptLocalSecret;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsSecret
    public synchronized TlsSecret hkdfExtract(int cryptoHashAlgorithm, TlsSecret ikm) {
        byte[] prk;
        checkAlive();
        byte[] salt = this.data;
        this.data = null;
        HMac hmac = new HMac(this.crypto.createDigest(cryptoHashAlgorithm));
        hmac.init(new KeyParameter(salt));
        convert(this.crypto, ikm).updateMac(hmac);
        prk = new byte[hmac.getMacSize()];
        hmac.doFinal(prk, 0);
        return this.crypto.adoptLocalSecret(prk);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.AbstractTlsSecret
    public AbstractTlsCrypto getCrypto() {
        return this.crypto;
    }

    /* access modifiers changed from: protected */
    public void hmacHash(Digest digest, byte[] secret, int secretOff, int secretLen, byte[] seed, byte[] output) {
        HMac mac = new HMac(digest);
        mac.init(new KeyParameter(secret, secretOff, secretLen));
        byte[] a = seed;
        int macSize = mac.getMacSize();
        byte[] b1 = new byte[macSize];
        byte[] b2 = new byte[macSize];
        for (int pos = 0; pos < output.length; pos += macSize) {
            mac.update(a, 0, a.length);
            mac.doFinal(b1, 0);
            a = b1;
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(b2, 0);
            System.arraycopy(b2, 0, output, pos, Math.min(macSize, output.length - pos));
        }
    }

    /* access modifiers changed from: protected */
    public byte[] prf(int prfAlgorithm, String label, byte[] seed, int length) {
        if (prfAlgorithm == 0) {
            return prf_SSL(seed, length);
        }
        byte[] labelSeed = Arrays.concatenate(Strings.toByteArray(label), seed);
        if (1 == prfAlgorithm) {
            return prf_1_0(labelSeed, length);
        }
        return prf_1_2(prfAlgorithm, labelSeed, length);
    }

    /* access modifiers changed from: protected */
    public byte[] prf_SSL(byte[] seed, int length) {
        Digest md5 = this.crypto.createDigest(1);
        Digest sha1 = this.crypto.createDigest(2);
        int md5Size = md5.getDigestSize();
        int sha1Size = sha1.getDigestSize();
        byte[] tmp = new byte[Math.max(md5Size, sha1Size)];
        byte[] result = new byte[length];
        int constLen = 1;
        int constPos = 0;
        int resultPos = 0;
        while (resultPos < length) {
            sha1.update(SSL3_CONST, constPos, constLen);
            constLen++;
            constPos += constLen;
            sha1.update(this.data, 0, this.data.length);
            sha1.update(seed, 0, seed.length);
            sha1.doFinal(tmp, 0);
            md5.update(this.data, 0, this.data.length);
            md5.update(tmp, 0, sha1Size);
            int remaining = length - resultPos;
            if (remaining < md5Size) {
                md5.doFinal(tmp, 0);
                System.arraycopy(tmp, 0, result, resultPos, remaining);
                resultPos += remaining;
            } else {
                md5.doFinal(result, resultPos);
                resultPos += md5Size;
            }
        }
        return result;
    }

    /* access modifiers changed from: protected */
    public byte[] prf_1_0(byte[] labelSeed, int length) {
        int s_half = (this.data.length + 1) / 2;
        byte[] b1 = new byte[length];
        hmacHash(this.crypto.createDigest(1), this.data, 0, s_half, labelSeed, b1);
        byte[] b2 = new byte[length];
        hmacHash(this.crypto.createDigest(2), this.data, this.data.length - s_half, s_half, labelSeed, b2);
        for (int i = 0; i < length; i++) {
            b1[i] = (byte) (b1[i] ^ b2[i]);
        }
        return b1;
    }

    /* access modifiers changed from: protected */
    public byte[] prf_1_2(int prfAlgorithm, byte[] labelSeed, int length) {
        byte[] result = new byte[length];
        hmacHash(this.crypto.createDigest(TlsCryptoUtils.getHashForPRF(prfAlgorithm)), this.data, 0, this.data.length, labelSeed, result);
        return result;
    }

    /* access modifiers changed from: protected */
    public synchronized void updateMac(Mac mac) {
        checkAlive();
        mac.update(this.data, 0, this.data.length);
    }
}
