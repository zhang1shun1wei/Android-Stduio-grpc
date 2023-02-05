package com.mi.car.jsse.easysec.tls.crypto;

import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import java.io.IOException;

public class TlsNullNullCipher implements TlsCipher {
    public static final TlsNullNullCipher INSTANCE = new TlsNullNullCipher();

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCipher
    public int getCiphertextDecodeLimit(int plaintextLimit) {
        return plaintextLimit;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCipher
    public int getCiphertextEncodeLimit(int plaintextLength, int plaintextLimit) {
        return plaintextLength;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCipher
    public int getPlaintextLimit(int ciphertextLimit) {
        return ciphertextLimit;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCipher
    public TlsEncodeResult encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion, int headerAllocation, byte[] plaintext, int offset, int len) throws IOException {
        byte[] result = new byte[(headerAllocation + len)];
        System.arraycopy(plaintext, offset, result, headerAllocation, len);
        return new TlsEncodeResult(result, 0, result.length, contentType);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCipher
    public TlsDecodeResult decodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion, byte[] ciphertext, int offset, int len) throws IOException {
        return new TlsDecodeResult(ciphertext, offset, len, recordType);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCipher
    public void rekeyDecoder() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCipher
    public void rekeyEncoder() throws IOException {
        throw new TlsFatalAlert((short) 80);
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.TlsCipher
    public boolean usesOpaqueRecordType() {
        return false;
    }
}
