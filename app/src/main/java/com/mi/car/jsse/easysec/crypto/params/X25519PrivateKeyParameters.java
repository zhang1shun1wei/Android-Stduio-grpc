package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.math.ec.rfc7748.X25519;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

public final class X25519PrivateKeyParameters extends AsymmetricKeyParameter {
    public static final int KEY_SIZE = 32;
    public static final int SECRET_SIZE = 32;
    private final byte[] data;

    public X25519PrivateKeyParameters(SecureRandom random) {
        super(true);
        this.data = new byte[32];
        X25519.generatePrivateKey(random, this.data);
    }

    public X25519PrivateKeyParameters(byte[] buf) {
        this(validate(buf), 0);
    }

    public X25519PrivateKeyParameters(byte[] buf, int off) {
        super(true);
        this.data = new byte[32];
        System.arraycopy(buf, off, this.data, 0, 32);
    }

    public X25519PrivateKeyParameters(InputStream input) throws IOException {
        super(true);
        this.data = new byte[32];
        if (32 != Streams.readFully(input, this.data)) {
            throw new EOFException("EOF encountered in middle of X25519 private key");
        }
    }

    public void encode(byte[] buf, int off) {
        System.arraycopy(this.data, 0, buf, off, 32);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.data);
    }

    public X25519PublicKeyParameters generatePublicKey() {
        byte[] publicKey = new byte[32];
        X25519.generatePublicKey(this.data, 0, publicKey, 0);
        return new X25519PublicKeyParameters(publicKey, 0);
    }

    public void generateSecret(X25519PublicKeyParameters publicKey, byte[] buf, int off) {
        byte[] encoded = new byte[32];
        publicKey.encode(encoded, 0);
        if (!X25519.calculateAgreement(this.data, 0, encoded, 0, buf, off)) {
            throw new IllegalStateException("X25519 agreement failed");
        }
    }

    private static byte[] validate(byte[] buf) {
        if (buf.length == 32) {
            return buf;
        }
        throw new IllegalArgumentException("'buf' must have length 32");
    }
}
