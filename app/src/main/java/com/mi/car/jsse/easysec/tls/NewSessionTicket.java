package com.mi.car.jsse.easysec.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class NewSessionTicket {
    protected byte[] ticket;
    protected long ticketLifetimeHint;

    public NewSessionTicket(long ticketLifetimeHint2, byte[] ticket2) {
        this.ticketLifetimeHint = ticketLifetimeHint2;
        this.ticket = ticket2;
    }

    public long getTicketLifetimeHint() {
        return this.ticketLifetimeHint;
    }

    public byte[] getTicket() {
        return this.ticket;
    }

    public void encode(OutputStream output) throws IOException {
        TlsUtils.writeUint32(this.ticketLifetimeHint, output);
        TlsUtils.writeOpaque16(this.ticket, output);
    }

    public static NewSessionTicket parse(InputStream input) throws IOException {
        return new NewSessionTicket(TlsUtils.readUint32(input), TlsUtils.readOpaque16(input));
    }
}
