package com.mi.car.jsse.easysec.tls;

import java.io.IOException;

public interface DatagramReceiver {
    int getReceiveLimit() throws IOException;

    int receive(byte[] bArr, int i, int i2, int i3) throws IOException;
}
