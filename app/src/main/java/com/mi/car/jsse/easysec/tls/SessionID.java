package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.encoders.Hex;

public final class SessionID implements Comparable {
    private final byte[] id;

    public SessionID(byte[] id2) {
        this.id = Arrays.clone(id2);
    }

    @Override // java.lang.Comparable
    public int compareTo(Object o) {
        return Arrays.compareUnsigned(this.id, ((SessionID) o).id);
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof SessionID)) {
            return false;
        }
        return Arrays.areEqual(this.id, ((SessionID) obj).id);
    }

    public byte[] getBytes() {
        return Arrays.clone(this.id);
    }

    public int hashCode() {
        return Arrays.hashCode(this.id);
    }

    public String toString() {
        return Hex.toHexString(this.id);
    }
}
