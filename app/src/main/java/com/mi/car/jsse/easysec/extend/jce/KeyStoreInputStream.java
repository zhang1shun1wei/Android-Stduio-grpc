package com.mi.car.jsse.easysec.extend.jce;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public class KeyStoreInputStream extends InputStream {
    @Override // java.io.InputStream
    public int read() throws IOException {
        throw new EOFException("mark user only");
    }
}
