package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.asn1.ocsp.ResponderID;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

public class OCSPStatusRequest {
    protected Extensions requestExtensions;
    protected Vector responderIDList;

    public OCSPStatusRequest(Vector responderIDList2, Extensions requestExtensions2) {
        this.responderIDList = responderIDList2;
        this.requestExtensions = requestExtensions2;
    }

    public Vector getResponderIDList() {
        return this.responderIDList;
    }

    public Extensions getRequestExtensions() {
        return this.requestExtensions;
    }

    public void encode(OutputStream output) throws IOException {
        if (this.responderIDList == null || this.responderIDList.isEmpty()) {
            TlsUtils.writeUint16(0, output);
        } else {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            for (int i = 0; i < this.responderIDList.size(); i++) {
                TlsUtils.writeOpaque16(((ResponderID) this.responderIDList.elementAt(i)).getEncoded("DER"), buf);
            }
            TlsUtils.checkUint16(buf.size());
            TlsUtils.writeUint16(buf.size(), output);
            Streams.writeBufTo(buf, output);
        }
        if (this.requestExtensions == null) {
            TlsUtils.writeUint16(0, output);
            return;
        }
        byte[] derEncoding = this.requestExtensions.getEncoded("DER");
        TlsUtils.checkUint16(derEncoding.length);
        TlsUtils.writeUint16(derEncoding.length, output);
        output.write(derEncoding);
    }

    public static OCSPStatusRequest parse(InputStream input) throws IOException {
        Vector responderIDList2 = new Vector();
        byte[] data = TlsUtils.readOpaque16(input);
        if (data.length > 0) {
            ByteArrayInputStream buf = new ByteArrayInputStream(data);
            do {
                byte[] derEncoding = TlsUtils.readOpaque16(buf, 1);
                ResponderID responderID = ResponderID.getInstance(TlsUtils.readASN1Object(derEncoding));
                TlsUtils.requireDEREncoding(responderID, derEncoding);
                responderIDList2.addElement(responderID);
            } while (buf.available() > 0);
        }
        Extensions requestExtensions2 = null;
        byte[] derEncoding2 = TlsUtils.readOpaque16(input);
        if (derEncoding2.length > 0) {
            Extensions extensions = Extensions.getInstance(TlsUtils.readASN1Object(derEncoding2));
            TlsUtils.requireDEREncoding(extensions, derEncoding2);
            requestExtensions2 = extensions;
        }
        return new OCSPStatusRequest(responderIDList2, requestExtensions2);
    }
}
