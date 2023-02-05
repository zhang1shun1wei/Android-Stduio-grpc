package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class PskIdentity {
    protected byte[] identity;
    protected long obfuscatedTicketAge;

    public PskIdentity(byte[] identity2, long obfuscatedTicketAge2) {
        if (identity2 == null) {
            throw new IllegalArgumentException("'identity' cannot be null");
        } else if (identity2.length < 1 || !TlsUtils.isValidUint16(identity2.length)) {
            throw new IllegalArgumentException("'identity' should have length from 1 to 65535");
        } else if (!TlsUtils.isValidUint32(obfuscatedTicketAge2)) {
            throw new IllegalArgumentException("'obfuscatedTicketAge' should be a uint32");
        } else {
            this.identity = identity2;
            this.obfuscatedTicketAge = obfuscatedTicketAge2;
        }
    }

    public int getEncodedLength() {
        return this.identity.length + 6;
    }

    public byte[] getIdentity() {
        return this.identity;
    }

    public long getObfuscatedTicketAge() {
        return this.obfuscatedTicketAge;
    }

    public void encode(OutputStream output) throws IOException {
        TlsUtils.writeOpaque16(this.identity, output);
        TlsUtils.writeUint32(this.obfuscatedTicketAge, output);
    }

    public static PskIdentity parse(InputStream input) throws IOException {
        return new PskIdentity(TlsUtils.readOpaque16(input, 1), TlsUtils.readUint32(input));
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof PskIdentity)) {
            return false;
        }
        PskIdentity that = (PskIdentity) obj;
        if (this.obfuscatedTicketAge != that.obfuscatedTicketAge || !Arrays.constantTimeAreEqual(this.identity, that.identity)) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return (Arrays.hashCode(this.identity) ^ ((int) this.obfuscatedTicketAge)) ^ ((int) (this.obfuscatedTicketAge >>> 32));
    }
}
