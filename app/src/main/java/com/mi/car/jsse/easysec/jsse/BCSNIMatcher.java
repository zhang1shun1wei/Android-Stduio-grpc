package com.mi.car.jsse.easysec.jsse;

import com.mi.car.jsse.easysec.tls.TlsUtils;

public abstract class BCSNIMatcher {
    private final int nameType;

    public abstract boolean matches(BCSNIServerName bCSNIServerName);

    protected BCSNIMatcher(int nameType2) {
        if (!TlsUtils.isValidUint8(nameType2)) {
            throw new IllegalArgumentException("'nameType' should be between 0 and 255");
        }
        this.nameType = nameType2;
    }

    public final int getType() {
        return this.nameType;
    }
}
