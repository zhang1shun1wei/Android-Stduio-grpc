package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.jce.exception.ExtException;

public class AnnotatedException extends Exception implements ExtException {
    private Throwable _underlyingException;

    public AnnotatedException(String string, Throwable e) {
        super(string);
        this._underlyingException = e;
    }

    public AnnotatedException(String string) {
        this(string, null);
    }

    /* access modifiers changed from: package-private */
    public Throwable getUnderlyingException() {
        return this._underlyingException;
    }

    @Override // com.mi.car.jsse.easysec.jce.exception.ExtException
    public Throwable getCause() {
        return this._underlyingException;
    }
}
