package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

/* access modifiers changed from: package-private */
public class Exceptions {
    Exceptions() {
    }

    static IllegalStateException illegalStateException(String message, Throwable cause) {
        return new IllegalStateException(message, cause);
    }

    static IllegalArgumentException illegalArgumentException(String message, Throwable cause) {
        return new IllegalArgumentException(message, cause);
    }
}
