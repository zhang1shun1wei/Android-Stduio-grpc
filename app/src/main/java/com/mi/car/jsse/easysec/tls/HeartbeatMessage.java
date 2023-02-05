package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class HeartbeatMessage {
    protected byte[] padding;
    protected byte[] payload;
    protected short type;

    public static HeartbeatMessage create(TlsContext context, short type2, byte[] payload2) {
        return create(context, type2, payload2, 16);
    }

    public static HeartbeatMessage create(TlsContext context, short type2, byte[] payload2, int paddingLength) {
        return new HeartbeatMessage(type2, payload2, context.getNonceGenerator().generateNonce(paddingLength));
    }

    public HeartbeatMessage(short type2, byte[] payload2, byte[] padding2) {
        if (!HeartbeatMessageType.isValid(type2)) {
            throw new IllegalArgumentException("'type' is not a valid HeartbeatMessageType value");
        } else if (payload2 == null || payload2.length >= 65536) {
            throw new IllegalArgumentException("'payload' must have length < 2^16");
        } else if (padding2 == null || padding2.length < 16) {
            throw new IllegalArgumentException("'padding' must have length >= 16");
        } else {
            this.type = type2;
            this.payload = payload2;
            this.padding = padding2;
        }
    }

    public int getPaddingLength() {
        return this.padding.length;
    }

    public byte[] getPayload() {
        return this.payload;
    }

    public short getType() {
        return this.type;
    }

    public void encode(OutputStream output) throws IOException {
        TlsUtils.writeUint8(this.type, output);
        TlsUtils.checkUint16(this.payload.length);
        TlsUtils.writeUint16(this.payload.length, output);
        output.write(this.payload);
        output.write(this.padding);
    }

    public static HeartbeatMessage parse(InputStream input) throws IOException {
        short type2 = TlsUtils.readUint8(input);
        if (!HeartbeatMessageType.isValid(type2)) {
            throw new TlsFatalAlert((short) 47);
        }
        int payload_length = TlsUtils.readUint16(input);
        PayloadBuffer buf = new PayloadBuffer();
        Streams.pipeAll(input, buf);
        byte[] payload2 = buf.getPayload(payload_length);
        if (payload2 == null) {
            return null;
        }
        return new HeartbeatMessage(type2, payload2, buf.getPadding(payload_length));
    }

    /* access modifiers changed from: package-private */
    public static class PayloadBuffer extends ByteArrayOutputStream {
        PayloadBuffer() {
        }

        /* access modifiers changed from: package-private */
        public byte[] getPayload(int payloadLength) {
            if (payloadLength > this.count - 16) {
                return null;
            }
            return Arrays.copyOf(this.buf, payloadLength);
        }

        /* access modifiers changed from: package-private */
        public byte[] getPadding(int payloadLength) {
            return TlsUtils.copyOfRangeExact(this.buf, payloadLength, this.count);
        }
    }
}
