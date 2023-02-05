package com.mi.car.jsse.easysec.asn1.eac;

import com.mi.car.jsse.easysec.asn1.ASN1ApplicationSpecific;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ParsingException;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERApplicationSpecific;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.util.Enumeration;

public class CVCertificateRequest extends ASN1Object {
    private static final int bodyValid = 1;
    private static final int signValid = 2;
    private CertificateBody certificateBody;
    private byte[] innerSignature = null;
    private final ASN1ApplicationSpecific original;
    private byte[] outerSignature = null;

    private CVCertificateRequest(ASN1ApplicationSpecific request) throws IOException {
        this.original = request;
        if (!request.isConstructed() || request.getApplicationTag() != 7) {
            initCertBody(request);
            return;
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(request.getObject(16));
        initCertBody(ASN1ApplicationSpecific.getInstance(seq.getObjectAt(0)));
        this.outerSignature = ASN1ApplicationSpecific.getInstance(seq.getObjectAt(seq.size() - 1)).getContents();
    }

    private void initCertBody(ASN1ApplicationSpecific request) throws IOException {
        if (request.getApplicationTag() == 33) {
            int valid = 0;
            Enumeration en = ASN1Sequence.getInstance(request.getObject(16)).getObjects();
            while (en.hasMoreElements()) {
                ASN1ApplicationSpecific obj = ASN1ApplicationSpecific.getInstance(en.nextElement());
                switch (obj.getApplicationTag()) {
                    case 55:
                        this.innerSignature = obj.getContents();
                        valid |= 2;
                        break;
                    case 78:
                        this.certificateBody = CertificateBody.getInstance(obj);
                        valid |= 1;
                        break;
                    default:
                        throw new IOException("Invalid tag, not an CV Certificate Request element:" + obj.getApplicationTag());
                }
            }
            if ((valid & 3) == 0) {
                throw new IOException("Invalid CARDHOLDER_CERTIFICATE in request:" + request.getApplicationTag());
            }
            return;
        }
        throw new IOException("not a CARDHOLDER_CERTIFICATE in request:" + request.getApplicationTag());
    }

    public static CVCertificateRequest getInstance(Object obj) {
        if (obj instanceof CVCertificateRequest) {
            return (CVCertificateRequest) obj;
        }
        if (obj == null) {
            return null;
        }
        try {
            return new CVCertificateRequest(ASN1ApplicationSpecific.getInstance(obj));
        } catch (IOException e) {
            throw new ASN1ParsingException("unable to parse data: " + e.getMessage(), e);
        }
    }

    public CertificateBody getCertificateBody() {
        return this.certificateBody;
    }

    public PublicKeyDataObject getPublicKey() {
        return this.certificateBody.getPublicKey();
    }

    public byte[] getInnerSignature() {
        return Arrays.clone(this.innerSignature);
    }

    public byte[] getOuterSignature() {
        return Arrays.clone(this.outerSignature);
    }

    public boolean hasOuterSignature() {
        return this.outerSignature != null;
    }

    public ASN1Primitive toASN1Primitive() {
        if (this.original != null) {
            return this.original;
        }
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.certificateBody);
        try {
            v.add(new DERApplicationSpecific(false, 55, new DEROctetString(this.innerSignature)));
            return new DERApplicationSpecific(33, v);
        } catch (IOException e) {
            throw new IllegalStateException("unable to convert signature!");
        }
    }
}
