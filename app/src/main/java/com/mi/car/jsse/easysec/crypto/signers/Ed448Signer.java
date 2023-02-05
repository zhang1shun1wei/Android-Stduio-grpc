package com.mi.car.jsse.easysec.crypto.signers;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.Signer;
import com.mi.car.jsse.easysec.crypto.params.Ed448PrivateKeyParameters;
import com.mi.car.jsse.easysec.crypto.params.Ed448PublicKeyParameters;
import com.mi.car.jsse.easysec.math.ec.rfc8032.Ed448;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.ByteArrayOutputStream;

public class Ed448Signer implements Signer {
    private final Buffer buffer = new Buffer();
    private final byte[] context;
    private boolean forSigning;
    private Ed448PrivateKeyParameters privateKey;
    private Ed448PublicKeyParameters publicKey;

    public Ed448Signer(byte[] context2) {
        this.context = Arrays.clone(context2);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void init(boolean forSigning2, CipherParameters parameters) {
        this.forSigning = forSigning2;
        if (forSigning2) {
            this.privateKey = (Ed448PrivateKeyParameters) parameters;
            this.publicKey = null;
        } else {
            this.privateKey = null;
            this.publicKey = (Ed448PublicKeyParameters) parameters;
        }
        reset();
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte b) {
        this.buffer.write(b);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void update(byte[] buf, int off, int len) {
        this.buffer.write(buf, off, len);
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public byte[] generateSignature() {
        if (this.forSigning && this.privateKey != null) {
            return this.buffer.generateSignature(this.privateKey, this.context);
        }
        throw new IllegalStateException("Ed448Signer not initialised for signature generation.");
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public boolean verifySignature(byte[] signature) {
        if (!this.forSigning && this.publicKey != null) {
            return this.buffer.verifySignature(this.publicKey, this.context, signature);
        }
        throw new IllegalStateException("Ed448Signer not initialised for verification");
    }

    @Override // com.mi.car.jsse.easysec.crypto.Signer
    public void reset() {
        this.buffer.reset();
    }

    /* access modifiers changed from: private */
    public static class Buffer extends ByteArrayOutputStream {
        private Buffer() {
        }

        /* access modifiers changed from: package-private */
        public synchronized byte[] generateSignature(Ed448PrivateKeyParameters privateKey, byte[] ctx) {
            byte[] signature;
            signature = new byte[114];
            privateKey.sign(0, ctx, this.buf, 0, this.count, signature, 0);
            reset();
            return signature;
        }

        /* access modifiers changed from: package-private */
        public synchronized boolean verifySignature(Ed448PublicKeyParameters publicKey, byte[] ctx, byte[] signature) {
            boolean z = false;
            synchronized (this) {
                if (114 != signature.length) {
                    reset();
                } else {
                    z = Ed448.verify(signature, 0, publicKey.getEncoded(), 0, ctx, this.buf, 0, this.count);
                    reset();
                }
            }
            return z;
        }

        public synchronized void reset() {
            Arrays.fill(this.buf, 0, this.count, (byte) 0);
            this.count = 0;
        }
    }
}
