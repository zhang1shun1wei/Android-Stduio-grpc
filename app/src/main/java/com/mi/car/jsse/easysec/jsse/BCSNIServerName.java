package com.mi.car.jsse.easysec.jsse;

import com.mi.car.jsse.easysec.tls.NameType;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.encoders.Hex;

public abstract class BCSNIServerName {
    private final byte[] encoded;
    private final int nameType;

    protected BCSNIServerName(int nameType2, byte[] encoded2) {
        if (!TlsUtils.isValidUint8(nameType2)) {
            throw new IllegalArgumentException("'nameType' should be between 0 and 255");
        } else if (encoded2 == null) {
            throw new NullPointerException("'encoded' cannot be null");
        } else {
            this.nameType = nameType2;
            this.encoded = TlsUtils.clone(encoded2);
        }
    }

    public final int getType() {
        return this.nameType;
    }

    public final byte[] getEncoded() {
        return TlsUtils.clone(this.encoded);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof BCSNIServerName)) {
            return false;
        }
        BCSNIServerName other = (BCSNIServerName) obj;
        return this.nameType == other.nameType && Arrays.areEqual(this.encoded, other.encoded);
    }

    public int hashCode() {
        return this.nameType ^ Arrays.hashCode(this.encoded);
    }

    public String toString() {
        return "{type=" + NameType.getText((short) this.nameType) + ", value=" + Hex.toHexString(this.encoded) + "}";
    }
}
