package com.mi.car.jsse.easysec.crypto.prng.drbg;

import com.mi.car.jsse.easysec.asn1.BERTags;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.Mac;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCSKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import com.mi.car.jsse.easysec.util.Integers;
import java.util.Hashtable;

/* access modifiers changed from: package-private */
public class Utils {
    static final Hashtable maxSecurityStrengths = new Hashtable();

    Utils() {
    }

    static {
        maxSecurityStrengths.put(McElieceCCA2KeyGenParameterSpec.SHA1, Integers.valueOf(128));
        maxSecurityStrengths.put(McElieceCCA2KeyGenParameterSpec.SHA224, Integers.valueOf(BERTags.PRIVATE));
        maxSecurityStrengths.put("SHA-256", Integers.valueOf(256));
        maxSecurityStrengths.put(McElieceCCA2KeyGenParameterSpec.SHA384, Integers.valueOf(256));
        maxSecurityStrengths.put("SHA-512", Integers.valueOf(256));
        maxSecurityStrengths.put("SHA-512/224", Integers.valueOf(BERTags.PRIVATE));
        maxSecurityStrengths.put(SPHINCSKeyParameters.SHA512_256, Integers.valueOf(256));
    }

    static int getMaxSecurityStrength(Digest d) {
        return ((Integer) maxSecurityStrengths.get(d.getAlgorithmName())).intValue();
    }

    static int getMaxSecurityStrength(Mac m) {
        String name = m.getAlgorithmName();
        return ((Integer) maxSecurityStrengths.get(name.substring(0, name.indexOf("/")))).intValue();
    }

    static byte[] hash_df(Digest digest, byte[] seedMaterial, int seedLength) {
        byte[] temp = new byte[((seedLength + 7) / 8)];
        int len = temp.length / digest.getDigestSize();
        int counter = 1;
        byte[] dig = new byte[digest.getDigestSize()];
        for (int i = 0; i <= len; i++) {
            digest.update((byte) counter);
            digest.update((byte) (seedLength >> 24));
            digest.update((byte) (seedLength >> 16));
            digest.update((byte) (seedLength >> 8));
            digest.update((byte) seedLength);
            digest.update(seedMaterial, 0, seedMaterial.length);
            digest.doFinal(dig, 0);
            System.arraycopy(dig, 0, temp, dig.length * i, temp.length - (dig.length * i) > dig.length ? dig.length : temp.length - (dig.length * i));
            counter++;
        }
        if (seedLength % 8 != 0) {
            int shift = 8 - (seedLength % 8);
            int carry = 0;
            for (int i2 = 0; i2 != temp.length; i2++) {
                int b = temp[i2] & 255;
                temp[i2] = (byte) ((b >>> shift) | (carry << (8 - shift)));
                carry = b;
            }
        }
        return temp;
    }

    static boolean isTooLarge(byte[] bytes, int maxBytes) {
        return bytes != null && bytes.length > maxBytes;
    }
}
