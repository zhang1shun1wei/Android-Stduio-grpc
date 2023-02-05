package com.mi.car.jsse.easysec.oer;

import com.mi.car.jsse.easysec.asn1.ASN1Absent;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class OEROptional extends ASN1Object {
    public static final OEROptional ABSENT = new OEROptional(false, null);
    private final boolean defined;
    private final ASN1Encodable value;

    private OEROptional(boolean defined2, ASN1Encodable value2) {
        this.defined = defined2;
        this.value = value2;
    }

    public static OEROptional getInstance(Object o) {
        if (o instanceof OEROptional) {
            return (OEROptional) o;
        }
        if (o instanceof ASN1Encodable) {
            return new OEROptional(true, (ASN1Encodable) o);
        }
        return ABSENT;
    }

    public static <T> T getValue(Class<T> type, Object src) {
        OEROptional o = getInstance(src);
        if (!o.defined) {
            return null;
        }
        return (T) o.getObject(type);
    }

    public <T> T getObject(final Class<T> type) {
        if (this.defined) {
            return this.value.getClass().isInstance(type) ? type.cast(this.value) : (T) AccessController.doPrivileged(new PrivilegedAction<T>() {
                /* class com.mi.car.jsse.easysec.oer.OEROptional.AnonymousClass1 */

                @Override // java.security.PrivilegedAction
                public T run() {
                    try {
                        Method m = type.getMethod("getInstance", Object.class);
                        return (T) type.cast(m.invoke(null, OEROptional.this.value));
                    } catch (Exception ex) {
                        throw new IllegalStateException("could not invoke getInstance on type " + ex.getMessage(), ex);
                    }
                }
            });
        }
        return null;
    }

    public ASN1Encodable get() {
        if (!this.defined) {
            return ABSENT;
        }
        return this.value;
    }

    public ASN1Primitive toASN1Primitive() {
        if (!this.defined) {
            return ASN1Absent.INSTANCE;
        }
        return get().toASN1Primitive();
    }

    public boolean isDefined() {
        return this.defined;
    }

    public String toString() {
        if (this.defined) {
            return "OPTIONAL(" + this.value + ")";
        }
        return "ABSENT";
    }

    public boolean equals(Object o) {
        boolean z = true;
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass() || !OEROptional.super.equals(o)) {
            return false;
        }
        OEROptional that = (OEROptional) o;
        if (this.defined != that.defined) {
            return false;
        }
        if (this.value != null) {
            z = this.value.equals(that.value);
        } else if (that.value != null) {
            z = false;
        }
        return z;
    }

    public int hashCode() {
        int i;
        int i2 = 0;
        int hashCode = OEROptional.super.hashCode() * 31;
        if (this.defined) {
            i = 1;
        } else {
            i = 0;
        }
        int i3 = (hashCode + i) * 31;
        if (this.value != null) {
            i2 = this.value.hashCode();
        }
        return i3 + i2;
    }
}
