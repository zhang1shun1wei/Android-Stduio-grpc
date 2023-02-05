package com.mi.car.jsse.easysec.util.io.pem;

import java.io.IOException;

public interface PemObjectParser {
    Object parseObject(PemObject pemObject) throws IOException;
}
