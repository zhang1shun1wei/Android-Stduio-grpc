package com.mi.car.jsse.easysec.asn1.eac;

import com.mi.car.jsse.easysec.asn1.ASN1ApplicationSpecific;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1InputStream;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1ParsingException;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.DERApplicationSpecific;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

public class CVCertificate extends ASN1Object {
    private static int bodyValid = 1;
    private static int signValid = 2;
    private CertificateBody certificateBody;
    private byte[] signature;
    private int valid;

    private void setPrivateData(ASN1ApplicationSpecific appSpe) throws IOException {
        this.valid = 0;
        if (appSpe.getApplicationTag() == 33) {
            ASN1InputStream content = new ASN1InputStream(appSpe.getContents());
            while (true) {
                ASN1Primitive tmpObj = content.readObject();
                if (tmpObj == null) {
                    content.close();
                    if (this.valid != (signValid | bodyValid)) {
                        throw new IOException("invalid CARDHOLDER_CERTIFICATE :" + appSpe.getApplicationTag());
                    }
                    return;
                } else if (tmpObj instanceof ASN1ApplicationSpecific) {
                    ASN1ApplicationSpecific aSpe = (ASN1ApplicationSpecific) tmpObj;
                    switch (aSpe.getApplicationTag()) {
                        case 55:
                            this.signature = aSpe.getContents();
                            this.valid |= signValid;
                            break;
                        case 78:
                            this.certificateBody = CertificateBody.getInstance(aSpe);
                            this.valid |= bodyValid;
                            break;
                        default:
                            throw new IOException("Invalid tag, not an Iso7816CertificateStructure :" + aSpe.getApplicationTag());
                    }
                } else {
                    throw new IOException("Invalid Object, not an Iso7816CertificateStructure");
                }
            }
        } else {
            throw new IOException("not a CARDHOLDER_CERTIFICATE :" + appSpe.getApplicationTag());
        }
    }

    public CVCertificate(ASN1InputStream aIS) throws IOException {
        initFrom(aIS);
    }

    private void initFrom(ASN1InputStream aIS) throws IOException {
        while (true) {
            ASN1Primitive obj = aIS.readObject();
            if (obj == null) {
                return;
            }
            if (obj instanceof ASN1ApplicationSpecific) {
                setPrivateData((ASN1ApplicationSpecific) obj);
            } else {
                throw new IOException("Invalid Input Stream for creating an Iso7816CertificateStructure");
            }
        }
    }

    private CVCertificate(ASN1ApplicationSpecific appSpe) throws IOException {
        setPrivateData(appSpe);
    }

    public CVCertificate(CertificateBody body, byte[] signature2) throws IOException {
        this.certificateBody = body;
        this.signature = Arrays.clone(signature2);
        this.valid |= bodyValid;
        this.valid |= signValid;
    }

    public static CVCertificate getInstance(Object obj) {
        if (obj instanceof CVCertificate) {
            return (CVCertificate) obj;
        }
        if (obj == null) {
            return null;
        }
        try {
            return new CVCertificate(ASN1ApplicationSpecific.getInstance(obj));
        } catch (IOException e) {
            throw new ASN1ParsingException("unable to parse data: " + e.getMessage(), e);
        }
    }

    public byte[] getSignature() {
        return Arrays.clone(this.signature);
    }

    public CertificateBody getBody() {
        return this.certificateBody;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.certificateBody);
        try {
            v.add(new DERApplicationSpecific(false, 55, new DEROctetString(this.signature)));
            return new DERApplicationSpecific(33, v);
        } catch (IOException e) {
            throw new IllegalStateException("unable to convert signature!");
        }
    }

    public ASN1ObjectIdentifier getHolderAuthorization() throws IOException {
        return this.certificateBody.getCertificateHolderAuthorization().getOid();
    }

    public PackedDate getEffectiveDate() throws IOException {
        return this.certificateBody.getCertificateEffectiveDate();
    }

    public int getCertificateType() {
        return this.certificateBody.getCertificateType();
    }

    public PackedDate getExpirationDate() throws IOException {
        return this.certificateBody.getCertificateExpirationDate();
    }

    public int getRole() throws IOException {
        return this.certificateBody.getCertificateHolderAuthorization().getAccessRights();
    }

    public CertificationAuthorityReference getAuthorityReference() throws IOException {
        return this.certificateBody.getCertificationAuthorityReference();
    }

    public CertificateHolderReference getHolderReference() throws IOException {
        return this.certificateBody.getCertificateHolderReference();
    }

    public int getHolderAuthorizationRole() throws IOException {
        return this.certificateBody.getCertificateHolderAuthorization().getAccessRights() & CertificateHolderAuthorization.CVCA;
    }

    public Flags getHolderAuthorizationRights() throws IOException {
        return new Flags(this.certificateBody.getCertificateHolderAuthorization().getAccessRights() & 31);
    }
}
