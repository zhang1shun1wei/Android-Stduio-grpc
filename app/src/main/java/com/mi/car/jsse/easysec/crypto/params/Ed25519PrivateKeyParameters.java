package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.math.ec.rfc8032.Ed25519;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

public final class Ed25519PrivateKeyParameters extends AsymmetricKeyParameter {
    public static final int KEY_SIZE = 32;
    public static final int SIGNATURE_SIZE = 64;
    private Ed25519PublicKeyParameters cachedPublicKey;
    private final byte[] data;

    public Ed25519PrivateKeyParameters(SecureRandom random) {
        super(true);
        this.data = new byte[32];
        Ed25519.generatePrivateKey(random, this.data);
    }

    public Ed25519PrivateKeyParameters(byte[] buf) {
        this(validate(buf), 0);
    }

    public Ed25519PrivateKeyParameters(byte[] buf, int off) {
        super(true);
        this.data = new byte[32];
        System.arraycopy(buf, off, this.data, 0, 32);
    }

    public Ed25519PrivateKeyParameters(InputStream input) throws IOException {
        super(true);
        this.data = new byte[32];
        if (32 != Streams.readFully(input, this.data)) {
            throw new EOFException("EOF encountered in middle of Ed25519 private key");
        }
    }

    public void encode(byte[] buf, int off) {
        System.arraycopy(this.data, 0, buf, off, 32);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.data);
    }

    public Ed25519PublicKeyParameters generatePublicKey() {
        Ed25519PublicKeyParameters ed25519PublicKeyParameters;
        synchronized (this.data) {
            if (this.cachedPublicKey == null) {
                byte[] publicKey = new byte[32];
                Ed25519.generatePublicKey(this.data, 0, publicKey, 0);
                this.cachedPublicKey = new Ed25519PublicKeyParameters(publicKey, 0);
            }
            ed25519PublicKeyParameters = this.cachedPublicKey;
        }
        return ed25519PublicKeyParameters;
    }

    public void sign(int algorithm, Ed25519PublicKeyParameters publicKey, byte[] ctx, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff) {
        sign(algorithm, ctx, msg, msgOff, msgLen, sig, sigOff);
    }

    public void sign(int algorithm, byte[] ctx, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff) {
        byte[] pk = new byte[32];
        generatePublicKey().encode(pk, 0);
        switch (algorithm) {
            case 0:
                if (ctx != null) {
                    throw new IllegalArgumentException("ctx");
                }
                Ed25519.sign(this.data, 0, pk, 0, msg, msgOff, msgLen, sig, sigOff);
                return;
            case 1:
                Ed25519.sign(this.data, 0, pk, 0, ctx, msg, msgOff, msgLen, sig, sigOff);
                return;
            case 2:
                if (64 != msgLen) {
                    throw new IllegalArgumentException("msgLen");
                }
                Ed25519.signPrehash(this.data, 0, pk, 0, ctx, msg, msgOff, sig, sigOff);
                return;
            default:
                throw new IllegalArgumentException("algorithm");
        }
    }

    private static byte[] validate(byte[] buf) {
        if (buf.length == 32) {
            return buf;
        }
        throw new IllegalArgumentException("'buf' must have length 32");
    }
}
