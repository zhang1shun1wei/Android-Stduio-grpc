package com.mi.car.jsse.easysec.tls.crypto;

import java.io.IOException;
import java.math.BigInteger;

public interface TlsSRP6Server {
    BigInteger calculateSecret(BigInteger bigInteger) throws IOException;

    BigInteger generateServerCredentials();
}
