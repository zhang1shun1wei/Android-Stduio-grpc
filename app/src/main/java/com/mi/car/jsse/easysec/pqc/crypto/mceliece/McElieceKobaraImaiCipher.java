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
import com.mi.car.jsse.easysec.pqc.math.linearalgebra.IntegerFunctions;
import java.security.SecureRandom;

public class McElieceKobaraImaiCipher implements MessageEncryptor {
    private static final String DEFAULT_PRNG_NAME = "SHA1PRNG";
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2.3";
    public static final byte[] PUBLIC_CONSTANT = "a predetermined public constant".getBytes();
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

    public int getKeySize(McElieceCCA2KeyParameters key2) {
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
        this.k = privKey.getK();
        this.t = privKey.getT();
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageEncryptor
    public byte[] messageEncrypt(byte[] input) {
        if (!this.forEncryption) {
            throw new IllegalStateException("cipher initialised for decryption");
        }
        int c2Len = this.messDigest.getDigestSize();
        int c4Len = this.k >> 3;
        int c5Len = (IntegerFunctions.binomial(this.n, this.t).bitLength() - 1) >> 3;
        int mLen = ((c4Len + c5Len) - c2Len) - PUBLIC_CONSTANT.length;
        if (input.length > mLen) {
            mLen = input.length;
        }
        int c1Len = mLen + PUBLIC_CONSTANT.length;
        int c6Len = ((c1Len + c2Len) - c4Len) - c5Len;
        byte[] mConst = new byte[c1Len];
        System.arraycopy(input, 0, mConst, 0, input.length);
        System.arraycopy(PUBLIC_CONSTANT, 0, mConst, mLen, PUBLIC_CONSTANT.length);
        byte[] r = new byte[c2Len];
        this.sr.nextBytes(r);
        DigestRandomGenerator sr0 = new DigestRandomGenerator(new SHA1Digest());
        sr0.addSeedMaterial(r);
        byte[] c1 = new byte[c1Len];
        sr0.nextBytes(c1);
        for (int i = c1Len - 1; i >= 0; i--) {
            c1[i] = (byte) (c1[i] ^ mConst[i]);
        }
        byte[] c2 = new byte[this.messDigest.getDigestSize()];
        this.messDigest.update(c1, 0, c1.length);
        this.messDigest.doFinal(c2, 0);
        for (int i2 = c2Len - 1; i2 >= 0; i2--) {
            c2[i2] = (byte) (c2[i2] ^ r[i2]);
        }
        byte[] c2c1 = ByteUtils.concatenate(c2, c1);
        byte[] c6 = new byte[0];
        if (c6Len > 0) {
            c6 = new byte[c6Len];
            System.arraycopy(c2c1, 0, c6, 0, c6Len);
        }
        byte[] c5 = new byte[c5Len];
        System.arraycopy(c2c1, c6Len, c5, 0, c5Len);
        byte[] c4 = new byte[c4Len];
        System.arraycopy(c2c1, c6Len + c5Len, c4, 0, c4Len);
        byte[] encC4 = McElieceCCA2Primitives.encryptionPrimitive((McElieceCCA2PublicKeyParameters) this.key, GF2Vector.OS2VP(this.k, c4), Conversions.encode(this.n, this.t, c5)).getEncoded();
        if (c6Len > 0) {
            return ByteUtils.concatenate(c6, encC4);
        }
        return encC4;
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageEncryptor
    public byte[] messageDecrypt(byte[] input) throws InvalidCipherTextException {
        byte[] c6;
        byte[] encC4;
        if (this.forEncryption) {
            throw new IllegalStateException("cipher initialised for decryption");
        }
        int nDiv8 = this.n >> 3;
        if (input.length < nDiv8) {
            throw new InvalidCipherTextException("Bad Padding: Ciphertext too short.");
        }
        int c2Len = this.messDigest.getDigestSize();
        int c4Len = this.k >> 3;
        int c5Len = (IntegerFunctions.binomial(this.n, this.t).bitLength() - 1) >> 3;
        int c6Len = input.length - nDiv8;
        if (c6Len > 0) {
            byte[][] c6EncC4 = ByteUtils.split(input, c6Len);
            c6 = c6EncC4[0];
            encC4 = c6EncC4[1];
        } else {
            c6 = new byte[0];
            encC4 = input;
        }
        GF2Vector[] c4z = McElieceCCA2Primitives.decryptionPrimitive((McElieceCCA2PrivateKeyParameters) this.key, GF2Vector.OS2VP(this.n, encC4));
        byte[] c4 = c4z[0].getEncoded();
        GF2Vector z = c4z[1];
        if (c4.length > c4Len) {
            c4 = ByteUtils.subArray(c4, 0, c4Len);
        }
        byte[] c5 = Conversions.decode(this.n, this.t, z);
        if (c5.length < c5Len) {
            byte[] paddedC5 = new byte[c5Len];
            System.arraycopy(c5, 0, paddedC5, c5Len - c5.length, c5.length);
            c5 = paddedC5;
        }
        byte[] c6c5c4 = ByteUtils.concatenate(ByteUtils.concatenate(c6, c5), c4);
        int c1Len = c6c5c4.length - c2Len;
        byte[][] c2c1 = ByteUtils.split(c6c5c4, c2Len);
        byte[] c2 = c2c1[0];
        byte[] c1 = c2c1[1];
        byte[] rPrime = new byte[this.messDigest.getDigestSize()];
        this.messDigest.update(c1, 0, c1.length);
        this.messDigest.doFinal(rPrime, 0);
        for (int i = c2Len - 1; i >= 0; i--) {
            rPrime[i] = (byte) (rPrime[i] ^ c2[i]);
        }
        DigestRandomGenerator sr0 = new DigestRandomGenerator(new SHA1Digest());
        sr0.addSeedMaterial(rPrime);
        byte[] mConstPrime = new byte[c1Len];
        sr0.nextBytes(mConstPrime);
        for (int i2 = c1Len - 1; i2 >= 0; i2--) {
            mConstPrime[i2] = (byte) (mConstPrime[i2] ^ c1[i2]);
        }
        if (mConstPrime.length < c1Len) {
            throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
        }
        byte[][] temp = ByteUtils.split(mConstPrime, c1Len - PUBLIC_CONSTANT.length);
        byte[] mr = temp[0];
        if (ByteUtils.equals(temp[1], PUBLIC_CONSTANT)) {
            return mr;
        }
        throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
    }
}
