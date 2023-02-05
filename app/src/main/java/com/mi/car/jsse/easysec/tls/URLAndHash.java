package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.Strings;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class URLAndHash {
    protected byte[] sha1Hash;
    protected String url;

    public URLAndHash(String url2, byte[] sha1Hash2) {
        if (TlsUtils.isNullOrEmpty(url2) || url2.length() >= 65536) {
            throw new IllegalArgumentException("'url' must have length from 1 to (2^16 - 1)");
        } else if (sha1Hash2 == null || sha1Hash2.length == 20) {
            this.url = url2;
            this.sha1Hash = sha1Hash2;
        } else {
            throw new IllegalArgumentException("'sha1Hash' must have length == 20, if present");
        }
    }

    public String getURL() {
        return this.url;
    }

    public byte[] getSHA1Hash() {
        return this.sha1Hash;
    }

    public void encode(OutputStream output) throws IOException {
        TlsUtils.writeOpaque16(Strings.toByteArray(this.url), output);
        if (this.sha1Hash == null) {
            TlsUtils.writeUint8(0, output);
            return;
        }
        TlsUtils.writeUint8(1, output);
        output.write(this.sha1Hash);
    }

    public static URLAndHash parse(TlsContext context, InputStream input) throws IOException {
        String url2 = Strings.fromByteArray(TlsUtils.readOpaque16(input, 1));
        byte[] sha1Hash2 = null;
        switch (TlsUtils.readUint8(input)) {
            case 0:
                if (TlsUtils.isTLSv12(context)) {
                    throw new TlsFatalAlert((short) 47);
                }
                break;
            case 1:
                sha1Hash2 = TlsUtils.readFully(20, input);
                break;
            default:
                throw new TlsFatalAlert((short) 47);
        }
        return new URLAndHash(url2, sha1Hash2);
    }
}
