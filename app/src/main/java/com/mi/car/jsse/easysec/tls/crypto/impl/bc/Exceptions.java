package com.mi.car.jsse.easysec.tls.crypto.impl.bc;

class Exceptions {
    Exceptions() {
    }

    static IllegalArgumentException illegalArgumentException(String message, Throwable cause) {
        return new IllegalArgumentException(message, cause);
    }
}
