package com.mi.car.jsse.easysec.pqc.crypto.util;

import com.mi.car.jsse.easysec.crypto.SecretWithEncapsulation;
import com.mi.car.jsse.easysec.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.security.auth.DestroyFailedException;

public class SecretWithEncapsulationImpl implements SecretWithEncapsulation {
    private final byte[] cipher_text;
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);
    private final byte[] sessionKey;

    public SecretWithEncapsulationImpl(byte[] sessionKey2, byte[] cipher_text2) {
        this.sessionKey = sessionKey2;
        this.cipher_text = cipher_text2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.SecretWithEncapsulation
    public byte[] getSecret() {
        checkDestroyed();
        return Arrays.clone(this.sessionKey);
    }

    @Override // com.mi.car.jsse.easysec.crypto.SecretWithEncapsulation
    public byte[] getEncapsulation() {
        checkDestroyed();
        return Arrays.clone(this.cipher_text);
    }

    @Override // javax.security.auth.Destroyable
    public void destroy() throws DestroyFailedException {
        if (!this.hasBeenDestroyed.getAndSet(true)) {
            Arrays.clear(this.sessionKey);
            Arrays.clear(this.cipher_text);
        }
    }

    public boolean isDestroyed() {
        return this.hasBeenDestroyed.get();
    }

    /* access modifiers changed from: package-private */
    public void checkDestroyed() {
        if (isDestroyed()) {
            throw new IllegalStateException("data has been destroyed");
        }
    }
}
