package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public final class Ed448PublicKeyParameters extends AsymmetricKeyParameter {
    public static final int KEY_SIZE = 57;
    private final byte[] data;

    public Ed448PublicKeyParameters(byte[] buf) {
        this(validate(buf), 0);
    }

    public Ed448PublicKeyParameters(byte[] buf, int off) {
        super(false);
        this.data = new byte[57];
        System.arraycopy(buf, off, this.data, 0, 57);
    }

    public Ed448PublicKeyParameters(InputStream input) throws IOException {
        super(false);
        this.data = new byte[57];
        if (57 != Streams.readFully(input, this.data)) {
            throw new EOFException("EOF encountered in middle of Ed448 public key");
        }
    }

    public void encode(byte[] buf, int off) {
        System.arraycopy(this.data, 0, buf, off, 57);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.data);
    }

    private static byte[] validate(byte[] buf) {
        if (buf.length == 57) {
            return buf;
        }
        throw new IllegalArgumentException("'buf' must have length 57");
    }
}
