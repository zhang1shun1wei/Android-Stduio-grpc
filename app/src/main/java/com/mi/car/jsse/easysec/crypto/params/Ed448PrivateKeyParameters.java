package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.math.ec.rfc8032.Ed448;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

public final class Ed448PrivateKeyParameters extends AsymmetricKeyParameter {
    public static final int KEY_SIZE = 57;
    public static final int SIGNATURE_SIZE = 114;
    private Ed448PublicKeyParameters cachedPublicKey;
    private final byte[] data;

    public Ed448PrivateKeyParameters(SecureRandom random) {
        super(true);
        this.data = new byte[57];
        Ed448.generatePrivateKey(random, this.data);
    }

    public Ed448PrivateKeyParameters(byte[] buf) {
        this(validate(buf), 0);
    }

    public Ed448PrivateKeyParameters(byte[] buf, int off) {
        super(true);
        this.data = new byte[57];
        System.arraycopy(buf, off, this.data, 0, 57);
    }

    public Ed448PrivateKeyParameters(InputStream input) throws IOException {
        super(true);
        this.data = new byte[57];
        if (57 != Streams.readFully(input, this.data)) {
            throw new EOFException("EOF encountered in middle of Ed448 private key");
        }
    }

    public void encode(byte[] buf, int off) {
        System.arraycopy(this.data, 0, buf, off, 57);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.data);
    }

    public Ed448PublicKeyParameters generatePublicKey() {
        Ed448PublicKeyParameters ed448PublicKeyParameters;
        synchronized (this.data) {
            if (this.cachedPublicKey == null) {
                byte[] publicKey = new byte[57];
                Ed448.generatePublicKey(this.data, 0, publicKey, 0);
                this.cachedPublicKey = new Ed448PublicKeyParameters(publicKey, 0);
            }
            ed448PublicKeyParameters = this.cachedPublicKey;
        }
        return ed448PublicKeyParameters;
    }

    public void sign(int algorithm, Ed448PublicKeyParameters publicKey, byte[] ctx, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff) {
        sign(algorithm, ctx, msg, msgOff, msgLen, sig, sigOff);
    }

    public void sign(int algorithm, byte[] ctx, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff) {
        byte[] pk = new byte[57];
        generatePublicKey().encode(pk, 0);
        switch (algorithm) {
            case 0:
                Ed448.sign(this.data, 0, pk, 0, ctx, msg, msgOff, msgLen, sig, sigOff);
                return;
            case 1:
                if (64 != msgLen) {
                    throw new IllegalArgumentException("msgLen");
                }
                Ed448.signPrehash(this.data, 0, pk, 0, ctx, msg, msgOff, sig, sigOff);
                return;
            default:
                throw new IllegalArgumentException("algorithm");
        }
    }

    private static byte[] validate(byte[] buf) {
        if (buf.length == 57) {
            return buf;
        }
        throw new IllegalArgumentException("'buf' must have length 57");
    }
}
