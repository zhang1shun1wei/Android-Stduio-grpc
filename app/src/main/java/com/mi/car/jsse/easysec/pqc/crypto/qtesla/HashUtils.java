package com.mi.car.jsse.easysec.pqc.crypto.qtesla;

import com.mi.car.jsse.easysec.crypto.digests.CSHAKEDigest;
import com.mi.car.jsse.easysec.crypto.digests.SHAKEDigest;

class HashUtils {
    static final int SECURE_HASH_ALGORITHM_KECCAK_128_RATE = 168;
    static final int SECURE_HASH_ALGORITHM_KECCAK_256_RATE = 136;

    HashUtils() {
    }

    static void secureHashAlgorithmKECCAK128(byte[] output, int outputOffset, int outputLength, byte[] input, int inputOffset, int inputLength) {
        SHAKEDigest dig = new SHAKEDigest(128);
        dig.update(input, inputOffset, inputLength);
        dig.doFinal(output, outputOffset, outputLength);
    }

    static void secureHashAlgorithmKECCAK256(byte[] output, int outputOffset, int outputLength, byte[] input, int inputOffset, int inputLength) {
        SHAKEDigest dig = new SHAKEDigest(256);
        dig.update(input, inputOffset, inputLength);
        dig.doFinal(output, outputOffset, outputLength);
    }

    static void customizableSecureHashAlgorithmKECCAK128Simple(byte[] output, int outputOffset, int outputLength, short continuousTimeStochasticModelling, byte[] input, int inputOffset, int inputLength) {
        CSHAKEDigest dig = new CSHAKEDigest(128, null, new byte[]{(byte) continuousTimeStochasticModelling, (byte) (continuousTimeStochasticModelling >> 8)});
        dig.update(input, inputOffset, inputLength);
        dig.doFinal(output, outputOffset, outputLength);
    }

    static void customizableSecureHashAlgorithmKECCAK256Simple(byte[] output, int outputOffset, int outputLength, short continuousTimeStochasticModelling, byte[] input, int inputOffset, int inputLength) {
        CSHAKEDigest dig = new CSHAKEDigest(256, null, new byte[]{(byte) continuousTimeStochasticModelling, (byte) (continuousTimeStochasticModelling >> 8)});
        dig.update(input, inputOffset, inputLength);
        dig.doFinal(output, outputOffset, outputLength);
    }
}
