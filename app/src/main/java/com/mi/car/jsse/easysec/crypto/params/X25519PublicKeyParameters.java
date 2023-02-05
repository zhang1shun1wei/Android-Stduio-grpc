package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public final class X25519PublicKeyParameters extends AsymmetricKeyParameter {
    public static final int KEY_SIZE = 32;
    private final byte[] data;

    public X25519PublicKeyParameters(byte[] buf) {
        this(validate(buf), 0);
    }

    public X25519PublicKeyParameters(byte[] buf, int off) {
        super(false);
        this.data = new byte[32];
        System.arraycopy(buf, off, this.data, 0, 32);
    }

    public X25519PublicKeyParameters(InputStream input) throws IOException {
        super(false);
        this.data = new byte[32];
        if (32 != Streams.readFully(input, this.data)) {
            throw new EOFException("EOF encountered in middle of X25519 public key");
        }
    }

    public void encode(byte[] buf, int off) {
        System.arraycopy(this.data, 0, buf, off, 32);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.data);
    }

    private static byte[] validate(byte[] buf) {
        if (buf.length == 32) {
            return buf;
        }
        throw new IllegalArgumentException("'buf' must have length 32");
    }
}
