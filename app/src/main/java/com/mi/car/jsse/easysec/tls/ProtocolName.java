package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class ProtocolName {
    public static final ProtocolName COAP = asUtf8Encoding("coap");
    public static final ProtocolName FTP = asUtf8Encoding("ftp");
    public static final ProtocolName HTTP_1_1 = asUtf8Encoding("http/1.1");
    public static final ProtocolName HTTP_2_TCP = asUtf8Encoding("h2c");
    public static final ProtocolName HTTP_2_TLS = asUtf8Encoding("h2");
    public static final ProtocolName IMAP = asUtf8Encoding("imap");
    public static final ProtocolName MANAGESIEVE = asUtf8Encoding("managesieve");
    public static final ProtocolName POP3 = asUtf8Encoding("pop3");
    public static final ProtocolName SPDY_1 = asUtf8Encoding("spdy/1");
    public static final ProtocolName SPDY_2 = asUtf8Encoding("spdy/2");
    public static final ProtocolName SPDY_3 = asUtf8Encoding("spdy/3");
    public static final ProtocolName STUN_NAT_DISCOVERY = asUtf8Encoding("stun.nat-discovery");
    public static final ProtocolName STUN_TURN = asUtf8Encoding("stun.turn");
    public static final ProtocolName WEBRTC = asUtf8Encoding("webrtc");
    public static final ProtocolName WEBRTC_CONFIDENTIAL = asUtf8Encoding("c-webrtc");
    public static final ProtocolName XMPP_CLIENT = asUtf8Encoding("xmpp-client");
    public static final ProtocolName XMPP_SERVER = asUtf8Encoding("xmpp-server");
    private final byte[] bytes;

    public static ProtocolName asRawBytes(byte[] bytes2) {
        return new ProtocolName(Arrays.clone(bytes2));
    }

    public static ProtocolName asUtf8Encoding(String name) {
        return new ProtocolName(Strings.toUTF8ByteArray(name));
    }

    private ProtocolName(byte[] bytes2) {
        if (bytes2 == null) {
            throw new IllegalArgumentException("'bytes' cannot be null");
        } else if (bytes2.length < 1 || bytes2.length > 255) {
            throw new IllegalArgumentException("'bytes' must have length from 1 to 255");
        } else {
            this.bytes = bytes2;
        }
    }

    public byte[] getBytes() {
        return Arrays.clone(this.bytes);
    }

    public String getUtf8Decoding() {
        return Strings.fromUTF8ByteArray(this.bytes);
    }

    public void encode(OutputStream output) throws IOException {
        TlsUtils.writeOpaque8(this.bytes, output);
    }

    public static ProtocolName parse(InputStream input) throws IOException {
        return new ProtocolName(TlsUtils.readOpaque8(input, 1));
    }

    public boolean equals(Object obj) {
        return (obj instanceof ProtocolName) && Arrays.areEqual(this.bytes, ((ProtocolName) obj).bytes);
    }

    public int hashCode() {
        return Arrays.hashCode(this.bytes);
    }
}
