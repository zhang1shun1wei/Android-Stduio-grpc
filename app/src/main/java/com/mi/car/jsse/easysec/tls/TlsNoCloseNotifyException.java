package com.mi.car.jsse.easysec.tls;

import java.io.EOFException;

public class TlsNoCloseNotifyException extends EOFException {
    public TlsNoCloseNotifyException() {
        super("No close_notify alert received before connection closed");
    }
}
