package com.mi.car.jsse.easysec.crypto;

public interface CharToByteConverter {
    byte[] convert(char[] cArr);

    String getType();
}
