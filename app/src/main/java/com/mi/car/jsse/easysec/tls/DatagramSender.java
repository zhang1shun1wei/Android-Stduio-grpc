package com.mi.car.jsse.easysec.tls;

import java.io.IOException;

public interface DatagramSender {
    int getSendLimit() throws IOException;

    void send(byte[] bArr, int i, int i2) throws IOException;
}
