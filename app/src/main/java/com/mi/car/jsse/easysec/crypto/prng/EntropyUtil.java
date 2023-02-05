package com.mi.car.jsse.easysec.crypto.prng;

public class EntropyUtil {
    public static byte[] generateSeed(EntropySource entropySource, int numBytes) {
        byte[] bytes = new byte[numBytes];
        if (numBytes * 8 <= entropySource.entropySize()) {
            System.arraycopy(entropySource.getEntropy(), 0, bytes, 0, bytes.length);
        } else {
            int entSize = entropySource.entropySize() / 8;
            for (int i = 0; i < bytes.length; i += entSize) {
                byte[] ent = entropySource.getEntropy();
                if (ent.length <= bytes.length - i) {
                    System.arraycopy(ent, 0, bytes, i, ent.length);
                } else {
                    System.arraycopy(ent, 0, bytes, i, bytes.length - i);
                }
            }
        }
        return bytes;
    }
}
