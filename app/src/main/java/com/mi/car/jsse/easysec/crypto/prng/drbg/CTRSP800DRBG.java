package com.mi.car.jsse.easysec.crypto.prng.drbg;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.prng.EntropySource;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.encoders.Hex;

public class CTRSP800DRBG implements SP80090DRBG {
    private static final int AES_MAX_BITS_REQUEST = 262144;
    private static final long AES_RESEED_MAX = 140737488355328L;
    private static final byte[] K_BITS = Hex.decodeStrict("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    private static final int TDEA_MAX_BITS_REQUEST = 4096;
    private static final long TDEA_RESEED_MAX = 2147483648L;
    private byte[] _Key;
    private byte[] _V;
    private BlockCipher _engine;
    private EntropySource _entropySource;
    private boolean _isTDEA = false;
    private int _keySizeInBits;
    private long _reseedCounter = 0;
    private int _securityStrength;
    private int _seedLength;

    public CTRSP800DRBG(BlockCipher engine, int keySizeInBits, int securityStrength, EntropySource entropySource, byte[] personalizationString, byte[] nonce) {
        this._entropySource = entropySource;
        this._engine = engine;
        this._keySizeInBits = keySizeInBits;
        this._securityStrength = securityStrength;
        this._seedLength = (engine.getBlockSize() * 8) + keySizeInBits;
        this._isTDEA = isTDEA(engine);
        if (securityStrength > 256) {
            throw new IllegalArgumentException("Requested security strength is not supported by the derivation function");
        } else if (getMaxSecurityStrength(engine, keySizeInBits) < securityStrength) {
            throw new IllegalArgumentException("Requested security strength is not supported by block cipher and key size");
        } else if (entropySource.entropySize() < securityStrength) {
            throw new IllegalArgumentException("Not enough entropy for security strength required");
        } else {
            CTR_DRBG_Instantiate_algorithm(getEntropy(), nonce, personalizationString);
        }
    }

    private void CTR_DRBG_Instantiate_algorithm(byte[] entropy, byte[] nonce, byte[] personalisationString) {
        byte[] seed = Block_Cipher_df(Arrays.concatenate(entropy, nonce, personalisationString), this._seedLength);
        int outlen = this._engine.getBlockSize();
        this._Key = new byte[((this._keySizeInBits + 7) / 8)];
        this._V = new byte[outlen];
        CTR_DRBG_Update(seed, this._Key, this._V);
        this._reseedCounter = 1;
    }

    private void CTR_DRBG_Update(byte[] seed, byte[] key, byte[] v) {
        byte[] temp = new byte[seed.length];
        byte[] outputBlock = new byte[this._engine.getBlockSize()];
        int outLen = this._engine.getBlockSize();
        this._engine.init(true, new KeyParameter(expandKey(key)));
        for (int i = 0; i * outLen < seed.length; i++) {
            addOneTo(v);
            this._engine.processBlock(v, 0, outputBlock, 0);
            System.arraycopy(outputBlock, 0, temp, i * outLen, temp.length - (i * outLen) > outLen ? outLen : temp.length - (i * outLen));
        }
        XOR(temp, seed, temp, 0);
        System.arraycopy(temp, 0, key, 0, key.length);
        System.arraycopy(temp, key.length, v, 0, v.length);
    }

    private void CTR_DRBG_Reseed_algorithm(byte[] additionalInput) {
        CTR_DRBG_Update(Block_Cipher_df(Arrays.concatenate(getEntropy(), additionalInput), this._seedLength), this._Key, this._V);
        this._reseedCounter = 1;
    }

    private void XOR(byte[] out, byte[] a, byte[] b, int bOff) {
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) (a[i] ^ b[i + bOff]);
        }
    }

    private void addOneTo(byte[] longer) {
        int carry = 1;
        for (int i = 1; i <= longer.length; i++) {
            int res = (longer[longer.length - i] & 255) + carry;
            carry = res > 255 ? 1 : 0;
            longer[longer.length - i] = (byte) res;
        }
    }

    private byte[] getEntropy() {
        byte[] entropy = this._entropySource.getEntropy();
        if (entropy.length >= (this._securityStrength + 7) / 8) {
            return entropy;
        }
        throw new IllegalStateException("Insufficient entropy provided by entropy source");
    }

    private byte[] Block_Cipher_df(byte[] inputString, int bitLength) {
        int outLen = this._engine.getBlockSize();
        int L = inputString.length;
        byte[] S = new byte[((((((L + 8) + 1) + outLen) - 1) / outLen) * outLen)];
        copyIntToByteArray(S, L, 0);
        copyIntToByteArray(S, bitLength / 8, 4);
        System.arraycopy(inputString, 0, S, 8, L);
        S[L + 8] = Byte.MIN_VALUE;
        byte[] temp = new byte[((this._keySizeInBits / 8) + outLen)];
        byte[] bccOut = new byte[outLen];
        byte[] IV = new byte[outLen];
        byte[] K = new byte[(this._keySizeInBits / 8)];
        System.arraycopy(K_BITS, 0, K, 0, K.length);
        for (int i = 0; i * outLen * 8 < this._keySizeInBits + (outLen * 8); i++) {
            copyIntToByteArray(IV, i, 0);
            BCC(bccOut, K, IV, S);
            System.arraycopy(bccOut, 0, temp, i * outLen, temp.length - (i * outLen) > outLen ? outLen : temp.length - (i * outLen));
        }
        byte[] X = new byte[outLen];
        System.arraycopy(temp, 0, K, 0, K.length);
        System.arraycopy(temp, K.length, X, 0, X.length);
        byte[] temp2 = new byte[(bitLength / 8)];
        this._engine.init(true, new KeyParameter(expandKey(K)));
        for (int i2 = 0; i2 * outLen < temp2.length; i2++) {
            this._engine.processBlock(X, 0, X, 0);
            System.arraycopy(X, 0, temp2, i2 * outLen, temp2.length - (i2 * outLen) > outLen ? outLen : temp2.length - (i2 * outLen));
        }
        return temp2;
    }

    private void BCC(byte[] bccOut, byte[] k, byte[] iV, byte[] data) {
        int outlen = this._engine.getBlockSize();
        byte[] chainingValue = new byte[outlen];
        int n = data.length / outlen;
        byte[] inputBlock = new byte[outlen];
        this._engine.init(true, new KeyParameter(expandKey(k)));
        this._engine.processBlock(iV, 0, chainingValue, 0);
        for (int i = 0; i < n; i++) {
            XOR(inputBlock, chainingValue, data, i * outlen);
            this._engine.processBlock(inputBlock, 0, chainingValue, 0);
        }
        System.arraycopy(chainingValue, 0, bccOut, 0, bccOut.length);
    }

    private void copyIntToByteArray(byte[] buf, int value, int offSet) {
        buf[offSet + 0] = (byte) (value >> 24);
        buf[offSet + 1] = (byte) (value >> 16);
        buf[offSet + 2] = (byte) (value >> 8);
        buf[offSet + 3] = (byte) value;
    }

    @Override // com.mi.car.jsse.easysec.crypto.prng.drbg.SP80090DRBG
    public int getBlockSize() {
        return this._V.length * 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.prng.drbg.SP80090DRBG
    public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant) {
        byte[] additionalInput2;
        int bytesToCopy;
        if (this._isTDEA) {
            if (this._reseedCounter > TDEA_RESEED_MAX) {
                return -1;
            }
            if (Utils.isTooLarge(output, 512)) {
                throw new IllegalArgumentException("Number of bits per request limited to 4096");
            }
        } else if (this._reseedCounter > AES_RESEED_MAX) {
            return -1;
        } else {
            if (Utils.isTooLarge(output, 32768)) {
                throw new IllegalArgumentException("Number of bits per request limited to 262144");
            }
        }
        if (predictionResistant) {
            CTR_DRBG_Reseed_algorithm(additionalInput);
            additionalInput = null;
        }
        if (additionalInput != null) {
            additionalInput2 = Block_Cipher_df(additionalInput, this._seedLength);
            CTR_DRBG_Update(additionalInput2, this._Key, this._V);
        } else {
            additionalInput2 = new byte[(this._seedLength / 8)];
        }
        byte[] out = new byte[this._V.length];
        this._engine.init(true, new KeyParameter(expandKey(this._Key)));
        for (int i = 0; i <= output.length / out.length; i++) {
            if (output.length - (out.length * i) > out.length) {
                bytesToCopy = out.length;
            } else {
                bytesToCopy = output.length - (this._V.length * i);
            }
            if (bytesToCopy != 0) {
                addOneTo(this._V);
                this._engine.processBlock(this._V, 0, out, 0);
                System.arraycopy(out, 0, output, out.length * i, bytesToCopy);
            }
        }
        CTR_DRBG_Update(additionalInput2, this._Key, this._V);
        this._reseedCounter++;
        return output.length * 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.prng.drbg.SP80090DRBG
    public void reseed(byte[] additionalInput) {
        CTR_DRBG_Reseed_algorithm(additionalInput);
    }

    private boolean isTDEA(BlockCipher cipher) {
        return cipher.getAlgorithmName().equals("DESede") || cipher.getAlgorithmName().equals("TDEA");
    }

    private int getMaxSecurityStrength(BlockCipher cipher, int keySizeInBits) {
        if (isTDEA(cipher) && keySizeInBits == 168) {
            return 112;
        }
        if (!cipher.getAlgorithmName().equals("AES")) {
            return -1;
        }
        return keySizeInBits;
    }

    /* access modifiers changed from: package-private */
    public byte[] expandKey(byte[] key) {
        if (!this._isTDEA) {
            return key;
        }
        byte[] tmp = new byte[24];
        padKey(key, 0, tmp, 0);
        padKey(key, 7, tmp, 8);
        padKey(key, 14, tmp, 16);
        return tmp;
    }

    private void padKey(byte[] keyMaster, int keyOff, byte[] tmp, int tmpOff) {
        tmp[tmpOff + 0] = (byte) (keyMaster[keyOff + 0] & 254);
        tmp[tmpOff + 1] = (byte) ((keyMaster[keyOff + 0] << 7) | ((keyMaster[keyOff + 1] & 252) >>> 1));
        tmp[tmpOff + 2] = (byte) ((keyMaster[keyOff + 1] << 6) | ((keyMaster[keyOff + 2] & 248) >>> 2));
        tmp[tmpOff + 3] = (byte) ((keyMaster[keyOff + 2] << 5) | ((keyMaster[keyOff + 3] & 240) >>> 3));
        tmp[tmpOff + 4] = (byte) ((keyMaster[keyOff + 3] << 4) | ((keyMaster[keyOff + 4] & 224) >>> 4));
        tmp[tmpOff + 5] = (byte) ((keyMaster[keyOff + 4] << 3) | ((keyMaster[keyOff + 5] & 192) >>> 5));
        tmp[tmpOff + 6] = (byte) ((keyMaster[keyOff + 5] << 2) | ((keyMaster[keyOff + 6] & 128) >>> 6));
        tmp[tmpOff + 7] = (byte) (keyMaster[keyOff + 6] << 1);
        for (int i = tmpOff; i <= tmpOff + 7; i++) {
            byte b = tmp[i];
            tmp[i] = (byte) ((b & 254) | (((((((((b >> 1) ^ (b >> 2)) ^ (b >> 3)) ^ (b >> 4)) ^ (b >> 5)) ^ (b >> 6)) ^ (b >> 7)) ^ 1) & 1));
        }
    }
}
