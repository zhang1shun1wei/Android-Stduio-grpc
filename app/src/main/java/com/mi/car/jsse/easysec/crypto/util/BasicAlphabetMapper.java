package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.crypto.AlphabetMapper;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import java.util.HashMap;
import java.util.Map;

public class BasicAlphabetMapper implements AlphabetMapper {
    private Map<Integer, Character> charMap;
    private Map<Character, Integer> indexMap;

    public BasicAlphabetMapper(String alphabet) {
        this(alphabet.toCharArray());
    }

    public BasicAlphabetMapper(char[] alphabet) {
        this.indexMap = new HashMap();
        this.charMap = new HashMap();
        for (int i = 0; i != alphabet.length; i++) {
            if (this.indexMap.containsKey(Character.valueOf(alphabet[i]))) {
                throw new IllegalArgumentException("duplicate key detected in alphabet: " + alphabet[i]);
            }
            this.indexMap.put(Character.valueOf(alphabet[i]), Integer.valueOf(i));
            this.charMap.put(Integer.valueOf(i), Character.valueOf(alphabet[i]));
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.AlphabetMapper
    public int getRadix() {
        return this.indexMap.size();
    }

    @Override // com.mi.car.jsse.easysec.crypto.AlphabetMapper
    public byte[] convertToIndexes(char[] input) {
        byte[] out;
        if (this.indexMap.size() <= 256) {
            out = new byte[input.length];
            for (int i = 0; i != input.length; i++) {
                out[i] = this.indexMap.get(Character.valueOf(input[i])).byteValue();
            }
        } else {
            out = new byte[(input.length * 2)];
            for (int i2 = 0; i2 != input.length; i2++) {
                int idx = this.indexMap.get(Character.valueOf(input[i2])).intValue();
                out[i2 * 2] = (byte) ((idx >> 8) & GF2Field.MASK);
                out[(i2 * 2) + 1] = (byte) (idx & GF2Field.MASK);
            }
        }
        return out;
    }

    @Override // com.mi.car.jsse.easysec.crypto.AlphabetMapper
    public char[] convertToChars(byte[] input) {
        char[] out;
        if (this.charMap.size() <= 256) {
            out = new char[input.length];
            for (int i = 0; i != input.length; i++) {
                out[i] = this.charMap.get(Integer.valueOf(input[i] & 255)).charValue();
            }
        } else if ((input.length & 1) != 0) {
            throw new IllegalArgumentException("two byte radix and input string odd length");
        } else {
            out = new char[(input.length / 2)];
            for (int i2 = 0; i2 != input.length; i2 += 2) {
                out[i2 / 2] = this.charMap.get(Integer.valueOf(((input[i2] << 8) & 65280) | (input[i2 + 1] & 255))).charValue();
            }
        }
        return out;
    }
}
