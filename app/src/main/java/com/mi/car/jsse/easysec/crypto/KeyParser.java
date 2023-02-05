package com.mi.car.jsse.easysec.crypto;

import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import java.io.IOException;
import java.io.InputStream;

public interface KeyParser {
    AsymmetricKeyParameter readKey(InputStream inputStream) throws IOException;
}
