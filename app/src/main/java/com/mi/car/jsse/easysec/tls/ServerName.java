package com.mi.car.jsse.easysec.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class ServerName {
    private final byte[] nameData;
    private final short nameType;

    public ServerName(short nameType2, byte[] nameData2) {
        if (!TlsUtils.isValidUint8(nameType2)) {
            throw new IllegalArgumentException("'nameType' must be from 0 to 255");
        } else if (nameData2 == null) {
            throw new NullPointerException("'nameData' cannot be null");
        } else if (nameData2.length < 1 || !TlsUtils.isValidUint16(nameData2.length)) {
            throw new IllegalArgumentException("'nameData' must have length from 1 to 65535");
        } else {
            this.nameType = nameType2;
            this.nameData = nameData2;
        }
    }

    public short getNameType() {
        return this.nameType;
    }

    public byte[] getNameData() {
        return this.nameData;
    }

    public void encode(OutputStream output) throws IOException {
        TlsUtils.writeUint8(this.nameType, output);
        TlsUtils.writeOpaque16(this.nameData, output);
    }

    public static ServerName parse(InputStream input) throws IOException {
        return new ServerName(TlsUtils.readUint8(input), TlsUtils.readOpaque16(input, 1));
    }
}
