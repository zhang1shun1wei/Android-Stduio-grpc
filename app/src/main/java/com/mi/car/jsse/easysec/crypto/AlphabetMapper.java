package com.mi.car.jsse.easysec.crypto;

public interface AlphabetMapper {
    char[] convertToChars(byte[] bArr);

    byte[] convertToIndexes(char[] cArr);

    int getRadix();
}
