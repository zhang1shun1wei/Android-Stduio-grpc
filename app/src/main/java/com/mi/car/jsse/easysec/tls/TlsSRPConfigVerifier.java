package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsSRPConfig;

public interface TlsSRPConfigVerifier {
    boolean accept(TlsSRPConfig tlsSRPConfig);
}
