package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.CipherKeyGenerator;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;

public class Poly1305KeyGenerator extends CipherKeyGenerator {
    private static final byte R_MASK_HIGH_4 = 15;
    private static final byte R_MASK_LOW_2 = -4;

    @Override // com.mi.car.jsse.easysec.crypto.CipherKeyGenerator
    public void init(KeyGenerationParameters param) {
        super.init(new KeyGenerationParameters(param.getRandom(), 256));
    }

    @Override // com.mi.car.jsse.easysec.crypto.CipherKeyGenerator
    public byte[] generateKey() {
        byte[] key = super.generateKey();
        clamp(key);
        return key;
    }

    public static void clamp(byte[] key) {
        if (key.length != 32) {
            throw new IllegalArgumentException("Poly1305 key must be 256 bits.");
        }
        key[3] = (byte) (key[3] & R_MASK_HIGH_4);
        key[7] = (byte) (key[7] & R_MASK_HIGH_4);
        key[11] = (byte) (key[11] & R_MASK_HIGH_4);
        key[15] = (byte) (key[15] & R_MASK_HIGH_4);
        key[4] = (byte) (key[4] & R_MASK_LOW_2);
        key[8] = (byte) (key[8] & R_MASK_LOW_2);
        key[12] = (byte) (key[12] & R_MASK_LOW_2);
    }

    public static void checkKey(byte[] key) {
        if (key.length != 32) {
            throw new IllegalArgumentException("Poly1305 key must be 256 bits.");
        }
        checkMask(key[3], R_MASK_HIGH_4);
        checkMask(key[7], R_MASK_HIGH_4);
        checkMask(key[11], R_MASK_HIGH_4);
        checkMask(key[15], R_MASK_HIGH_4);
        checkMask(key[4], R_MASK_LOW_2);
        checkMask(key[8], R_MASK_LOW_2);
        checkMask(key[12], R_MASK_LOW_2);
    }

    private static void checkMask(byte b, byte mask) {
        if (((mask ^ -1) & b) != 0) {
            throw new IllegalArgumentException("Invalid format for r portion of Poly1305 key.");
        }
    }
}
