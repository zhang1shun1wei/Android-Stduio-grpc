package com.mi.car.jsse.easysec.util.encoders;

import java.io.IOException;
import java.io.OutputStream;

public interface Encoder {
    int decode(String str, OutputStream outputStream) throws IOException;

    int decode(byte[] bArr, int i, int i2, OutputStream outputStream) throws IOException;

    int encode(byte[] bArr, int i, int i2, OutputStream outputStream) throws IOException;

    int getEncodedLength(int i);

    int getMaxDecodedLength(int i);
}
