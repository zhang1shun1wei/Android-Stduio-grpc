package com.mi.car.jsse.easysec.tls.crypto;

import com.mi.car.jsse.easysec.tls.TlsException;

public class TlsCryptoException extends TlsException {
    public TlsCryptoException(String msg) {
        super(msg);
    }

    public TlsCryptoException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
