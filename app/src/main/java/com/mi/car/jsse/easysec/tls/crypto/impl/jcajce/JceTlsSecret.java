package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.tls.CipherSuite;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.tls.crypto.impl.AbstractTlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.impl.AbstractTlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class JceTlsSecret extends AbstractTlsSecret {
    private static final byte[] SSL3_CONST = generateSSL3Constants();
    protected final JcaTlsCrypto crypto;

    public static JceTlsSecret convert(JcaTlsCrypto crypto, TlsSecret secret) {
        if (secret instanceof JceTlsSecret) {
            return (JceTlsSecret)secret;
        } else if (secret instanceof AbstractTlsSecret) {
            AbstractTlsSecret abstractTlsSecret = (AbstractTlsSecret)secret;
            return crypto.adoptLocalSecret(copyData(abstractTlsSecret));
        } else {
            throw new IllegalArgumentException("unrecognized TlsSecret - cannot copy data: " + secret.getClass().getName());
        }
    }

    private static byte[] generateSSL3Constants() {
        int n = 15;
        byte[] result = new byte[n * (n + 1) / 2];
        int pos = 0;

        for(int i = 0; i < n; ++i) {
            byte b = (byte)(65 + i);

            for(int j = 0; j <= i; ++j) {
                result[pos++] = b;
            }
        }

        return result;
    }

    public JceTlsSecret(JcaTlsCrypto crypto, byte[] data) {
        super(data);
        this.crypto = crypto;
    }

    public synchronized TlsSecret deriveUsingPRF(int prfAlgorithm, String label, byte[] seed, int length) {
        this.checkAlive();

        try {
            switch(prfAlgorithm) {
                case 4:
                    return TlsCryptoUtils.hkdfExpandLabel(this, 4, label, seed, length);
                case 5:
                    return TlsCryptoUtils.hkdfExpandLabel(this, 5, label, seed, length);
                case 6:
                default:
                    return this.crypto.adoptLocalSecret(this.prf(prfAlgorithm, label, seed, length));
                case 7:
                    return TlsCryptoUtils.hkdfExpandLabel(this, 7, label, seed, length);
            }
        } catch (Exception var6) {
            throw new RuntimeException(var6);
        }
    }

    public synchronized TlsSecret hkdfExpand(int cryptoHashAlgorithm, byte[] info, int length) {
        if (length < 1) {
            return this.crypto.adoptLocalSecret(TlsUtils.EMPTY_BYTES);
        } else {
            int hashLen = TlsCryptoUtils.getHashOutputSize(cryptoHashAlgorithm);
            if (length > 255 * hashLen) {
                throw new IllegalArgumentException("'length' must be <= 255 * (output size of 'hashAlgorithm')");
            } else {
                this.checkAlive();
                byte[] prk = this.data;

                try {
                    String algorithm = this.crypto.getHMACAlgorithmName(cryptoHashAlgorithm);
                    Mac hmac = this.crypto.getHelper().createMac(algorithm);
                    hmac.init(new SecretKeySpec(prk, 0, prk.length, algorithm));
                    byte[] okm = new byte[length];
                    byte[] t = new byte[hashLen];
                    byte counter = 0;
                    int pos = 0;

                    while(true) {
                        hmac.update(info, 0, info.length);
                        ++counter;
                        hmac.update(counter);
                        hmac.doFinal(t, 0);
                        int remaining = length - pos;
                        if (remaining <= hashLen) {
                            System.arraycopy(t, 0, okm, pos, remaining);
                            return this.crypto.adoptLocalSecret(okm);
                        }

                        System.arraycopy(t, 0, okm, pos, hashLen);
                        pos += hashLen;
                        hmac.update(t, 0, t.length);
                    }
                } catch (GeneralSecurityException var13) {
                    throw new RuntimeException(var13);
                }
            }
        }
    }

    public synchronized TlsSecret hkdfExtract(int cryptoHashAlgorithm, TlsSecret ikm) {
        this.checkAlive();
        byte[] salt = this.data;
        this.data = null;

        try {
            String algorithm = this.crypto.getHMACAlgorithmName(cryptoHashAlgorithm);
            Mac hmac = this.crypto.getHelper().createMac(algorithm);
            hmac.init(new SecretKeySpec(salt, 0, salt.length, algorithm));
            convert(this.crypto, ikm).updateMac(hmac);
            byte[] prk = hmac.doFinal();
            return this.crypto.adoptLocalSecret(prk);
        } catch (GeneralSecurityException var7) {
            throw new RuntimeException(var7);
        }
    }

    public AbstractTlsCrypto getCrypto() {
        return this.crypto;
    }

    protected void hmacHash(String digestName, byte[] secret, int secretOff, int secretLen, byte[] seed, byte[] output) throws GeneralSecurityException {
        String macName = "Hmac" + digestName;
        Mac mac = this.crypto.getHelper().createMac(macName);
        mac.init(new SecretKeySpec(secret, secretOff, secretLen, macName));
        byte[] a = seed;
        int macSize = mac.getMacLength();
        byte[] b1 = new byte[macSize];
        byte[] b2 = new byte[macSize];

        for(int pos = 0; pos < output.length; pos += macSize) {
            mac.update(a, 0, a.length);
            mac.doFinal(b1, 0);
            a = b1;
            mac.update(b1, 0, b1.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(b2, 0);
            System.arraycopy(b2, 0, output, pos, Math.min(macSize, output.length - pos));
        }

    }

    protected byte[] prf(int prfAlgorithm, String label, byte[] seed, int length) throws GeneralSecurityException {
        if (0 == prfAlgorithm) {
            return this.prf_SSL(seed, length);
        } else {
            byte[] labelSeed = Arrays.concatenate(Strings.toByteArray(label), seed);
            return 1 == prfAlgorithm ? this.prf_1_0(labelSeed, length) : this.prf_1_2(prfAlgorithm, labelSeed, length);
        }
    }

    protected byte[] prf_SSL(byte[] seed, int length) throws GeneralSecurityException {
        MessageDigest md5 = this.crypto.getHelper().createDigest("MD5");
        MessageDigest sha1 = this.crypto.getHelper().createDigest("SHA-1");
        int md5Size = md5.getDigestLength();
        int sha1Size = sha1.getDigestLength();
        byte[] tmp = new byte[Math.max(md5Size, sha1Size)];
        byte[] result = new byte[length];
        int constLen = 1;
        int constPos = 0;
        int resultPos = 0;

        while(resultPos < length) {
            sha1.update(SSL3_CONST, constPos, constLen);
            constPos += constLen++;
            sha1.update(this.data, 0, this.data.length);
            sha1.update(seed, 0, seed.length);
            sha1.digest(tmp, 0, sha1Size);
            md5.update(this.data, 0, this.data.length);
            md5.update(tmp, 0, sha1Size);
            int remaining = length - resultPos;
            if (remaining < md5Size) {
                md5.digest(tmp, 0, md5Size);
                System.arraycopy(tmp, 0, result, resultPos, remaining);
                resultPos += remaining;
            } else {
                md5.digest(result, resultPos, md5Size);
                resultPos += md5Size;
            }
        }

        return result;
    }

    protected byte[] prf_1_0(byte[] labelSeed, int length) throws GeneralSecurityException {
        int s_half = (this.data.length + 1) / 2;
        byte[] b1 = new byte[length];
        this.hmacHash("MD5", this.data, 0, s_half, labelSeed, b1);
        byte[] b2 = new byte[length];
        this.hmacHash("SHA1", this.data, this.data.length - s_half, s_half, labelSeed, b2);

        for(int i = 0; i < length; ++i) {
            b1[i] ^= b2[i];
        }

        return b1;
    }

    protected byte[] prf_1_2(int prfAlgorithm, byte[] labelSeed, int length) throws GeneralSecurityException {
        String digestName = this.crypto.getDigestName(TlsCryptoUtils.getHashForPRF(prfAlgorithm)).replaceAll("-", "");
        byte[] result = new byte[length];
        this.hmacHash(digestName, this.data, 0, this.data.length, labelSeed, result);
        return result;
    }

    protected synchronized void updateMac(Mac mac) {
        this.checkAlive();
        mac.update(this.data, 0, this.data.length);
    }
}
