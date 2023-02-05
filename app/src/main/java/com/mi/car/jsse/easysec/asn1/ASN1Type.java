package com.mi.car.jsse.easysec.asn1;

/* access modifiers changed from: package-private */
public abstract class ASN1Type {
    final Class javaClass;

    ASN1Type(Class javaClass2) {
        this.javaClass = javaClass2;
    }

    /* access modifiers changed from: package-private */
    public final Class getJavaClass() {
        return this.javaClass;
    }

    public final boolean equals(Object that) {
        return this == that;
    }

    public final int hashCode() {
        return super.hashCode();
    }
}
