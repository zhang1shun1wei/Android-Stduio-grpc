package com.mi.car.jsse.easysec.util;

import java.io.IOException;

public interface Encodable {
    byte[] getEncoded() throws IOException;
}
