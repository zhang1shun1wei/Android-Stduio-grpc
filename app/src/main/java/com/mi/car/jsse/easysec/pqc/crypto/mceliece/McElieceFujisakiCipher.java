package com.mi.car.jsse.easysec.pqc.crypto.mceliece;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.digests.SHA1Digest;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.crypto.prng.DigestRandomGenerator;
import com.mi.car.jsse.easysec.pqc.crypto.MessageEncryptor;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.ByteUtils;
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.GF2Vector;
import java.security.SecureRandom;

public class McElieceFujisakiCipher implements MessageEncryptor {
    private static final String DEFAULT_PRNG_NAME = "SHA1PRNG";
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2.1";
    private boolean forEncryption;
    private int k;
    McElieceCCA2KeyParameters key;
    private Digest messDigest;
    private int n;
    private SecureRandom sr;
    private int t;

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageEncryptor
    public void init(boolean forEncryption2, CipherParameters param) {
        this.forEncryption = forEncryption2;
        if (!forEncryption2) {
            this.key = (McElieceCCA2PrivateKeyParameters) param;
            initCipherDecrypt((McElieceCCA2PrivateKeyParameters) this.key);
        } else if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.sr = rParam.getRandom();
            this.key = (McElieceCCA2PublicKeyParameters) rParam.getParameters();
            initCipherEncrypt((McElieceCCA2PublicKeyParameters) this.key);
        } else {
            this.sr = CryptoServicesRegistrar.getSecureRandom();
            this.key = (McElieceCCA2PublicKeyParameters) param;
            initCipherEncrypt((McElieceCCA2PublicKeyParameters) this.key);
        }
    }

    public int getKeySize(McElieceCCA2KeyParameters key2) throws IllegalArgumentException {
        if (key2 instanceof McElieceCCA2PublicKeyParameters) {
            return ((McElieceCCA2PublicKeyParameters) key2).getN();
        }
        if (key2 instanceof McElieceCCA2PrivateKeyParameters) {
            return ((McElieceCCA2PrivateKeyParameters) key2).getN();
        }
        throw new IllegalArgumentException("unsupported type");
    }

    private void initCipherEncrypt(McElieceCCA2PublicKeyParameters pubKey) {
        this.messDigest = Utils.getDigest(pubKey.getDigest());
        this.n = pubKey.getN();
        this.k = pubKey.getK();
        this.t = pubKey.getT();
    }

    private void initCipherDecrypt(McElieceCCA2PrivateKeyParameters privKey) {
        this.messDigest = Utils.getDigest(privKey.getDigest());
        this.n = privKey.getN();
        this.t = privKey.getT();
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageEncryptor
    public byte[] messageEncrypt(byte[] input) {
        if (!this.forEncryption) {
            throw new IllegalStateException("cipher initialised for decryption");
        }
        GF2Vector r = new GF2Vector(this.k, this.sr);
        byte[] rBytes = r.getEncoded();
        byte[] rm = ByteUtils.concatenate(rBytes, input);
        this.messDigest.update(rm, 0, rm.length);
        byte[] hrm = new byte[this.messDigest.getDigestSize()];
        this.messDigest.doFinal(hrm, 0);
        byte[] c1 = McElieceCCA2Primitives.encryptionPrimitive((McElieceCCA2PublicKeyParameters) this.key, r, Conversions.encode(this.n, this.t, hrm)).getEncoded();
        DigestRandomGenerator sr0 = new DigestRandomGenerator(new SHA1Digest());
        sr0.addSeedMaterial(rBytes);
        byte[] c2 = new byte[input.length];
        sr0.nextBytes(c2);
        for (int i = 0; i < input.length; i++) {
            c2[i] = (byte) (c2[i] ^ input[i]);
        }
        return ByteUtils.concatenate(c1, c2);
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageEncryptor
    public byte[] messageDecrypt(byte[] input) throws InvalidCipherTextException {
        if (this.forEncryption) {
            throw new IllegalStateException("cipher initialised for decryption");
        }
        int c1Len = (this.n + 7) >> 3;
        int c2Len = input.length - c1Len;
        byte[][] c1c2 = ByteUtils.split(input, c1Len);
        byte[] c1 = c1c2[0];
        byte[] c2 = c1c2[1];
        GF2Vector[] decC1 = McElieceCCA2Primitives.decryptionPrimitive((McElieceCCA2PrivateKeyParameters) this.key, GF2Vector.OS2VP(this.n, c1));
        byte[] rBytes = decC1[0].getEncoded();
        GF2Vector z = decC1[1];
        DigestRandomGenerator sr0 = new DigestRandomGenerator(new SHA1Digest());
        sr0.addSeedMaterial(rBytes);
        byte[] mBytes = new byte[c2Len];
        sr0.nextBytes(mBytes);
        for (int i = 0; i < c2Len; i++) {
            mBytes[i] = (byte) (mBytes[i] ^ c2[i]);
        }
        byte[] rmBytes = ByteUtils.concatenate(rBytes, mBytes);
        byte[] hrm = new byte[this.messDigest.getDigestSize()];
        this.messDigest.update(rmBytes, 0, rmBytes.length);
        this.messDigest.doFinal(hrm, 0);
        if (Conversions.encode(this.n, this.t, hrm).equals(z)) {
            return mBytes;
        }
        throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
    }
}
