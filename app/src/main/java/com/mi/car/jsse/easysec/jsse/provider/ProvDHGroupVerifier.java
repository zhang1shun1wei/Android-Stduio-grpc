package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.tls.DefaultTlsDHGroupVerifier;
import com.mi.car.jsse.easysec.tls.crypto.DHGroup;

class ProvDHGroupVerifier extends DefaultTlsDHGroupVerifier {
    private static final int provMinimumPrimeBits = PropertyUtils.getIntegerSystemProperty("com.mi.car.jsse.easysec.jsse.client.dh.minimumPrimeBits", DefaultTlsDHGroupVerifier.DEFAULT_MINIMUM_PRIME_BITS, 1024, 16384);
    private static final boolean provUnrestrictedGroups = PropertyUtils.getBooleanSystemProperty("com.mi.car.jsse.easysec.jsse.client.dh.unrestrictedGroups", false);

    ProvDHGroupVerifier() {
        super(provMinimumPrimeBits);
    }

    /* access modifiers changed from: protected */
    @Override // com.mi.car.jsse.easysec.tls.DefaultTlsDHGroupVerifier
    public boolean checkGroup(DHGroup dhGroup) {
        return provUnrestrictedGroups || super.checkGroup(dhGroup);
    }
}
