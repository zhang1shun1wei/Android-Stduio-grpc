package com.mi.car.jsse.easysec.tls;

import java.io.IOException;
import java.io.InterruptedIOException;

public class DTLSTransport implements DatagramTransport {
    private final DTLSRecordLayer recordLayer;

    DTLSTransport(DTLSRecordLayer recordLayer2) {
        this.recordLayer = recordLayer2;
    }

    @Override // com.mi.car.jsse.easysec.tls.DatagramReceiver
    public int getReceiveLimit() throws IOException {
        return this.recordLayer.getReceiveLimit();
    }

    @Override // com.mi.car.jsse.easysec.tls.DatagramSender
    public int getSendLimit() throws IOException {
        return this.recordLayer.getSendLimit();
    }

    @Override // com.mi.car.jsse.easysec.tls.DatagramReceiver
    public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
        if (buf == null) {
            throw new NullPointerException("'buf' cannot be null");
        } else if (off < 0 || off >= buf.length) {
            throw new IllegalArgumentException("'off' is an invalid offset: " + off);
        } else if (len < 0 || len > buf.length - off) {
            throw new IllegalArgumentException("'len' is an invalid length: " + len);
        } else if (waitMillis < 0) {
            throw new IllegalArgumentException("'waitMillis' cannot be negative");
        } else {
            try {
                return this.recordLayer.receive(buf, off, len, waitMillis);
            } catch (TlsFatalAlert fatalAlert) {
                this.recordLayer.fail(fatalAlert.getAlertDescription());
                throw fatalAlert;
            } catch (InterruptedIOException e) {
                throw e;
            } catch (IOException e2) {
                this.recordLayer.fail((short) 80);
                throw e2;
            } catch (RuntimeException e3) {
                this.recordLayer.fail((short) 80);
                throw new TlsFatalAlert((short) 80, (Throwable) e3);
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.DatagramSender
    public void send(byte[] buf, int off, int len) throws IOException {
        if (buf == null) {
            throw new NullPointerException("'buf' cannot be null");
        } else if (off < 0 || off >= buf.length) {
            throw new IllegalArgumentException("'off' is an invalid offset: " + off);
        } else if (len < 0 || len > buf.length - off) {
            throw new IllegalArgumentException("'len' is an invalid length: " + len);
        } else {
            try {
                this.recordLayer.send(buf, off, len);
            } catch (TlsFatalAlert fatalAlert) {
                this.recordLayer.fail(fatalAlert.getAlertDescription());
                throw fatalAlert;
            } catch (InterruptedIOException e) {
                throw e;
            } catch (IOException e2) {
                this.recordLayer.fail((short) 80);
                throw e2;
            } catch (RuntimeException e3) {
                this.recordLayer.fail((short) 80);
                throw new TlsFatalAlert((short) 80, (Throwable) e3);
            }
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.TlsCloseable
    public void close() throws IOException {
        this.recordLayer.close();
    }
}
