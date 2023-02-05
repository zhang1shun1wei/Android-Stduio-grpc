package com.mi.car.jsse.easysec.crypto.prng;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.crypto.engines.DESedeEngine;
import com.mi.car.jsse.easysec.crypto.macs.HMac;
import com.mi.car.jsse.easysec.crypto.prng.drbg.CTRSP800DRBG;
import com.mi.car.jsse.easysec.crypto.prng.drbg.HMacSP800DRBG;
import com.mi.car.jsse.easysec.crypto.prng.drbg.HashSP800DRBG;
import com.mi.car.jsse.easysec.crypto.prng.drbg.SP80090DRBG;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;

public class SP800SecureRandomBuilder {
    private int entropyBitsRequired;
    private final EntropySourceProvider entropySourceProvider;
    private byte[] personalizationString;
    private final SecureRandom random;
    private int securityStrength;

    public SP800SecureRandomBuilder() {
        this(CryptoServicesRegistrar.getSecureRandom(), false);
    }

    public SP800SecureRandomBuilder(SecureRandom entropySource, boolean predictionResistant) {
        this.securityStrength = 256;
        this.entropyBitsRequired = 256;
        this.random = entropySource;
        this.entropySourceProvider = new BasicEntropySourceProvider(this.random, predictionResistant);
    }

    public SP800SecureRandomBuilder(EntropySourceProvider entropySourceProvider2) {
        this.securityStrength = 256;
        this.entropyBitsRequired = 256;
        this.random = null;
        this.entropySourceProvider = entropySourceProvider2;
    }

    public SP800SecureRandomBuilder setPersonalizationString(byte[] personalizationString2) {
        this.personalizationString = Arrays.clone(personalizationString2);
        return this;
    }

    public SP800SecureRandomBuilder setSecurityStrength(int securityStrength2) {
        this.securityStrength = securityStrength2;
        return this;
    }

    public SP800SecureRandomBuilder setEntropyBitsRequired(int entropyBitsRequired2) {
        this.entropyBitsRequired = entropyBitsRequired2;
        return this;
    }

    public SP800SecureRandom buildHash(Digest digest, byte[] nonce, boolean predictionResistant) {
        return new SP800SecureRandom(this.random, this.entropySourceProvider.get(this.entropyBitsRequired), new HashDRBGProvider(digest, nonce, this.personalizationString, this.securityStrength), predictionResistant);
    }

    public SP800SecureRandom buildCTR(BlockCipher cipher, int keySizeInBits, byte[] nonce, boolean predictionResistant) {
        return new SP800SecureRandom(this.random, this.entropySourceProvider.get(this.entropyBitsRequired), new CTRDRBGProvider(cipher, keySizeInBits, nonce, this.personalizationString, this.securityStrength), predictionResistant);
    }

    public SP800SecureRandom buildHMAC(Mac hMac, byte[] nonce, boolean predictionResistant) {
        return new SP800SecureRandom(this.random, this.entropySourceProvider.get(this.entropyBitsRequired), new HMacDRBGProvider(hMac, nonce, this.personalizationString, this.securityStrength), predictionResistant);
    }

    private static class HashDRBGProvider implements DRBGProvider {
        private final Digest digest;
        private final byte[] nonce;
        private final byte[] personalizationString;
        private final int securityStrength;

        public HashDRBGProvider(Digest digest2, byte[] nonce2, byte[] personalizationString2, int securityStrength2) {
            this.digest = digest2;
            this.nonce = nonce2;
            this.personalizationString = personalizationString2;
            this.securityStrength = securityStrength2;
        }

        @Override // com.mi.car.jsse.easysec.crypto.prng.DRBGProvider
        public String getAlgorithm() {
            return "HASH-DRBG-" + SP800SecureRandomBuilder.getSimplifiedName(this.digest);
        }

        @Override // com.mi.car.jsse.easysec.crypto.prng.DRBGProvider
        public SP80090DRBG get(EntropySource entropySource) {
            return new HashSP800DRBG(this.digest, this.securityStrength, entropySource, this.personalizationString, this.nonce);
        }
    }

    private static class HMacDRBGProvider implements DRBGProvider {
        private final Mac hMac;
        private final byte[] nonce;
        private final byte[] personalizationString;
        private final int securityStrength;

        public HMacDRBGProvider(Mac hMac2, byte[] nonce2, byte[] personalizationString2, int securityStrength2) {
            this.hMac = hMac2;
            this.nonce = nonce2;
            this.personalizationString = personalizationString2;
            this.securityStrength = securityStrength2;
        }

        @Override // com.mi.car.jsse.easysec.crypto.prng.DRBGProvider
        public String getAlgorithm() {
            if (this.hMac instanceof HMac) {
                return "HMAC-DRBG-" + SP800SecureRandomBuilder.getSimplifiedName(((HMac) this.hMac).getUnderlyingDigest());
            }
            return "HMAC-DRBG-" + this.hMac.getAlgorithmName();
        }

        @Override // com.mi.car.jsse.easysec.crypto.prng.DRBGProvider
        public SP80090DRBG get(EntropySource entropySource) {
            return new HMacSP800DRBG(this.hMac, this.securityStrength, entropySource, this.personalizationString, this.nonce);
        }
    }

    private static class CTRDRBGProvider implements DRBGProvider {
        private final BlockCipher blockCipher;
        private final int keySizeInBits;
        private final byte[] nonce;
        private final byte[] personalizationString;
        private final int securityStrength;

        public CTRDRBGProvider(BlockCipher blockCipher2, int keySizeInBits2, byte[] nonce2, byte[] personalizationString2, int securityStrength2) {
            this.blockCipher = blockCipher2;
            this.keySizeInBits = keySizeInBits2;
            this.nonce = nonce2;
            this.personalizationString = personalizationString2;
            this.securityStrength = securityStrength2;
        }

        @Override // com.mi.car.jsse.easysec.crypto.prng.DRBGProvider
        public String getAlgorithm() {
            if (this.blockCipher instanceof DESedeEngine) {
                return "CTR-DRBG-3KEY-TDES";
            }
            return "CTR-DRBG-" + this.blockCipher.getAlgorithmName() + this.keySizeInBits;
        }

        @Override // com.mi.car.jsse.easysec.crypto.prng.DRBGProvider
        public SP80090DRBG get(EntropySource entropySource) {
            return new CTRSP800DRBG(this.blockCipher, this.keySizeInBits, this.securityStrength, entropySource, this.personalizationString, this.nonce);
        }
    }

    /* access modifiers changed from: private */
    public static String getSimplifiedName(Digest digest) {
        String name = digest.getAlgorithmName();
        int dIndex = name.indexOf(45);
        if (dIndex <= 0 || name.startsWith("SHA3")) {
            return name;
        }
        return name.substring(0, dIndex) + name.substring(dIndex + 1);
    }
}
