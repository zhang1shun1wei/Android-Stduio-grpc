package com.mi.car.jsse.easysec.crypto.prng.drbg;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.prng.EntropySource;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCSKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Integers;
import java.util.Hashtable;

public class HashSP800DRBG implements SP80090DRBG {
    private static final int MAX_BITS_REQUEST = 262144;
    private static final byte[] ONE = {1};
    private static final long RESEED_MAX = 140737488355328L;
    private static final Hashtable seedlens = new Hashtable();
    private byte[] _C;
    private byte[] _V;
    private Digest _digest;
    private EntropySource _entropySource;
    private long _reseedCounter;
    private int _securityStrength;
    private int _seedLength;

    static {
        seedlens.put(McElieceCCA2KeyGenParameterSpec.SHA1, Integers.valueOf(440));
        seedlens.put(McElieceCCA2KeyGenParameterSpec.SHA224, Integers.valueOf(440));
        seedlens.put("SHA-256", Integers.valueOf(440));
        seedlens.put(SPHINCSKeyParameters.SHA512_256, Integers.valueOf(440));
        seedlens.put("SHA-512/224", Integers.valueOf(440));
        seedlens.put(McElieceCCA2KeyGenParameterSpec.SHA384, Integers.valueOf(888));
        seedlens.put("SHA-512", Integers.valueOf(888));
    }

    public HashSP800DRBG(Digest digest, int securityStrength, EntropySource entropySource, byte[] personalizationString, byte[] nonce) {
        if (securityStrength > Utils.getMaxSecurityStrength(digest)) {
            throw new IllegalArgumentException("Requested security strength is not supported by the derivation function");
        } else if (entropySource.entropySize() < securityStrength) {
            throw new IllegalArgumentException("Not enough entropy for security strength required");
        } else {
            this._digest = digest;
            this._entropySource = entropySource;
            this._securityStrength = securityStrength;
            this._seedLength = ((Integer) seedlens.get(digest.getAlgorithmName())).intValue();
            this._V = Utils.hash_df(this._digest, Arrays.concatenate(getEntropy(), nonce, personalizationString), this._seedLength);
            byte[] subV = new byte[(this._V.length + 1)];
            System.arraycopy(this._V, 0, subV, 1, this._V.length);
            this._C = Utils.hash_df(this._digest, subV, this._seedLength);
            this._reseedCounter = 1;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.prng.drbg.SP80090DRBG
    public int getBlockSize() {
        return this._digest.getDigestSize() * 8;
    }

    @Override // com.mi.car.jsse.easysec.crypto.prng.drbg.SP80090DRBG
    public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant) {
        int numberOfBits = output.length * 8;
        if (numberOfBits > MAX_BITS_REQUEST) {
            throw new IllegalArgumentException("Number of bits per request limited to 262144");
        } else if (this._reseedCounter > RESEED_MAX) {
            return -1;
        } else {
            if (predictionResistant) {
                reseed(additionalInput);
                additionalInput = null;
            }
            if (additionalInput != null) {
                byte[] newInput = new byte[(this._V.length + 1 + additionalInput.length)];
                newInput[0] = 2;
                System.arraycopy(this._V, 0, newInput, 1, this._V.length);
                System.arraycopy(additionalInput, 0, newInput, this._V.length + 1, additionalInput.length);
                addTo(this._V, hash(newInput));
            }
            byte[] rv = hashgen(this._V, numberOfBits);
            byte[] subH = new byte[(this._V.length + 1)];
            System.arraycopy(this._V, 0, subH, 1, this._V.length);
            subH[0] = 3;
            addTo(this._V, hash(subH));
            addTo(this._V, this._C);
            addTo(this._V, new byte[]{(byte) ((int) (this._reseedCounter >> 24)), (byte) ((int) (this._reseedCounter >> 16)), (byte) ((int) (this._reseedCounter >> 8)), (byte) ((int) this._reseedCounter)});
            this._reseedCounter++;
            System.arraycopy(rv, 0, output, 0, output.length);
            return numberOfBits;
        }
    }

    private byte[] getEntropy() {
        byte[] entropy = this._entropySource.getEntropy();
        if (entropy.length >= (this._securityStrength + 7) / 8) {
            return entropy;
        }
        throw new IllegalStateException("Insufficient entropy provided by entropy source");
    }

    private void addTo(byte[] longer, byte[] shorter) {
        int carry = 0;
        for (int i = 1; i <= shorter.length; i++) {
            int res = (longer[longer.length - i] & 255) + (shorter[shorter.length - i] & 255) + carry;
            carry = res > 255 ? 1 : 0;
            longer[longer.length - i] = (byte) res;
        }
        for (int i2 = shorter.length + 1; i2 <= longer.length; i2++) {
            int res2 = (longer[longer.length - i2] & 255) + carry;
            carry = res2 > 255 ? 1 : 0;
            longer[longer.length - i2] = (byte) res2;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.prng.drbg.SP80090DRBG
    public void reseed(byte[] additionalInput) {
        this._V = Utils.hash_df(this._digest, Arrays.concatenate(ONE, this._V, getEntropy(), additionalInput), this._seedLength);
        byte[] subV = new byte[(this._V.length + 1)];
        subV[0] = 0;
        System.arraycopy(this._V, 0, subV, 1, this._V.length);
        this._C = Utils.hash_df(this._digest, subV, this._seedLength);
        this._reseedCounter = 1;
    }

    private byte[] hash(byte[] input) {
        byte[] hash = new byte[this._digest.getDigestSize()];
        doHash(input, hash);
        return hash;
    }

    private void doHash(byte[] input, byte[] output) {
        this._digest.update(input, 0, input.length);
        this._digest.doFinal(output, 0);
    }

    private byte[] hashgen(byte[] input, int lengthInBits) {
        int m = (lengthInBits / 8) / this._digest.getDigestSize();
        byte[] data = new byte[input.length];
        System.arraycopy(input, 0, data, 0, input.length);
        byte[] W = new byte[(lengthInBits / 8)];
        byte[] dig = new byte[this._digest.getDigestSize()];
        for (int i = 0; i <= m; i++) {
            doHash(data, dig);
            System.arraycopy(dig, 0, W, dig.length * i, W.length - (dig.length * i) > dig.length ? dig.length : W.length - (dig.length * i));
            addTo(data, ONE);
        }
        return W;
    }
}
