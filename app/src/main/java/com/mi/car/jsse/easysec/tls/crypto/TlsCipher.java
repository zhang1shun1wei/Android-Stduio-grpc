package com.mi.car.jsse.easysec.tls.crypto;

import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import java.io.IOException;

public interface TlsCipher {
    TlsDecodeResult decodeCiphertext(long j, short s, ProtocolVersion protocolVersion, byte[] bArr, int i, int i2) throws IOException;

    TlsEncodeResult encodePlaintext(long j, short s, ProtocolVersion protocolVersion, int i, byte[] bArr, int i2, int i3) throws IOException;

    int getCiphertextDecodeLimit(int i);

    int getCiphertextEncodeLimit(int i, int i2);

    int getPlaintextLimit(int i);

    void rekeyDecoder() throws IOException;

    void rekeyEncoder() throws IOException;

    boolean usesOpaqueRecordType();
}
