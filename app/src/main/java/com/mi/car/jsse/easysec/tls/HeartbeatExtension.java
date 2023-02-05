package com.mi.car.jsse.easysec.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class HeartbeatExtension {
    protected short mode;

    public HeartbeatExtension(short mode2) {
        if (!HeartbeatMode.isValid(mode2)) {
            throw new IllegalArgumentException("'mode' is not a valid HeartbeatMode value");
        }
        this.mode = mode2;
    }

    public short getMode() {
        return this.mode;
    }

    public void encode(OutputStream output) throws IOException {
        TlsUtils.writeUint8(this.mode, output);
    }

    public static HeartbeatExtension parse(InputStream input) throws IOException {
        short mode2 = TlsUtils.readUint8(input);
        if (HeartbeatMode.isValid(mode2)) {
            return new HeartbeatExtension(mode2);
        }
        throw new TlsFatalAlert((short) 47);
    }
}
