package com.mi.car.jsse.easysec.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class KeyShareEntry {
    protected final byte[] keyExchange;
    protected final int namedGroup;

    private static boolean checkKeyExchangeLength(int length) {
        return length > 0 && length < 65536;
    }

    public KeyShareEntry(int namedGroup2, byte[] keyExchange2) {
        if (!TlsUtils.isValidUint16(namedGroup2)) {
            throw new IllegalArgumentException("'namedGroup' should be a uint16");
        } else if (keyExchange2 == null) {
            throw new NullPointerException("'keyExchange' cannot be null");
        } else if (!checkKeyExchangeLength(keyExchange2.length)) {
            throw new IllegalArgumentException("'keyExchange' must have length from 1 to (2^16 - 1)");
        } else {
            this.namedGroup = namedGroup2;
            this.keyExchange = keyExchange2;
        }
    }

    public int getNamedGroup() {
        return this.namedGroup;
    }

    public byte[] getKeyExchange() {
        return this.keyExchange;
    }

    public void encode(OutputStream output) throws IOException {
        TlsUtils.writeUint16(getNamedGroup(), output);
        TlsUtils.writeOpaque16(getKeyExchange(), output);
    }

    public static KeyShareEntry parse(InputStream input) throws IOException {
        return new KeyShareEntry(TlsUtils.readUint16(input), TlsUtils.readOpaque16(input, 1));
    }
}
