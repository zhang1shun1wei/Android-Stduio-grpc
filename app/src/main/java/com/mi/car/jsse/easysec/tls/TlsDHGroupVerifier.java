package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.DHGroup;

public interface TlsDHGroupVerifier {
    boolean accept(DHGroup dHGroup);
}
