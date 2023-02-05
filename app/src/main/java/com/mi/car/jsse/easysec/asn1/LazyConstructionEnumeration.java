package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.NoSuchElementException;

class LazyConstructionEnumeration implements Enumeration {
    private ASN1InputStream aIn;
    private Object nextObj = readObject();

    public LazyConstructionEnumeration(byte[] encoded) {
        this.aIn = new ASN1InputStream(encoded, true);
    }

    public boolean hasMoreElements() {
        return this.nextObj != null;
    }

    @Override // java.util.Enumeration
    public Object nextElement() {
        if (this.nextObj != null) {
            Object o = this.nextObj;
            this.nextObj = readObject();
            return o;
        }
        throw new NoSuchElementException();
    }

    private Object readObject() {
        try {
            return this.aIn.readObject();
        } catch (IOException e) {
            throw new ASN1ParsingException("malformed ASN.1: " + e, e);
        }
    }
}
