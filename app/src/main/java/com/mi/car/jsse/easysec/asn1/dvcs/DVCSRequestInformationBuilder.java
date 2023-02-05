package com.mi.car.jsse.easysec.asn1.dvcs;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import com.mi.car.jsse.easysec.asn1.x509.GeneralNames;
import com.mi.car.jsse.easysec.asn1.x509.PolicyInformation;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.math.BigInteger;

public class DVCSRequestInformationBuilder {
    private static final int DEFAULT_VERSION = 1;
    private static final int TAG_DATA_LOCATIONS = 3;
    private static final int TAG_DVCS = 2;
    private static final int TAG_EXTENSIONS = 4;
    private static final int TAG_REQUESTER = 0;
    private static final int TAG_REQUEST_POLICY = 1;
    private GeneralNames dataLocations;
    private GeneralNames dvcs;
    private Extensions extensions;
    private DVCSRequestInformation initialInfo;
    private BigInteger nonce;
    private PolicyInformation requestPolicy;
    private DVCSTime requestTime;
    private GeneralNames requester;
    private final ServiceType service;
    private int version = 1;

    public DVCSRequestInformationBuilder(ServiceType service2) {
        this.service = service2;
    }

    public DVCSRequestInformationBuilder(DVCSRequestInformation initialInfo2) {
        this.initialInfo = initialInfo2;
        this.service = initialInfo2.getService();
        this.version = initialInfo2.getVersion();
        this.nonce = initialInfo2.getNonce();
        this.requestTime = initialInfo2.getRequestTime();
        this.requestPolicy = initialInfo2.getRequestPolicy();
        this.dvcs = initialInfo2.getDVCS();
        this.dataLocations = initialInfo2.getDataLocations();
    }

    public DVCSRequestInformation build() {
        ASN1EncodableVector v = new ASN1EncodableVector(9);
        if (this.version != 1) {
            v.add(new ASN1Integer((long) this.version));
        }
        v.add(this.service);
        if (this.nonce != null) {
            v.add(new ASN1Integer(this.nonce));
        }
        if (this.requestTime != null) {
            v.add(this.requestTime);
        }
        int[] tags = {0, 1, 2, 3, 4};
        ASN1Encodable[] taggedObjects = {this.requester, this.requestPolicy, this.dvcs, this.dataLocations, this.extensions};
        for (int i = 0; i < tags.length; i++) {
            int tag = tags[i];
            ASN1Encodable taggedObject = taggedObjects[i];
            if (taggedObject != null) {
                v.add(new DERTaggedObject(false, tag, taggedObject));
            }
        }
        return DVCSRequestInformation.getInstance(new DERSequence(v));
    }

    public void setVersion(int version2) {
        if (this.initialInfo != null) {
            throw new IllegalStateException("cannot change version in existing DVCSRequestInformation");
        }
        this.version = version2;
    }

    public void setNonce(BigInteger nonce2) {
        if (this.initialInfo != null) {
            if (this.initialInfo.getNonce() == null) {
                this.nonce = nonce2;
            } else {
                byte[] initialBytes = this.initialInfo.getNonce().toByteArray();
                byte[] newBytes = BigIntegers.asUnsignedByteArray(nonce2);
                byte[] nonceBytes = new byte[(initialBytes.length + newBytes.length)];
                System.arraycopy(initialBytes, 0, nonceBytes, 0, initialBytes.length);
                System.arraycopy(newBytes, 0, nonceBytes, initialBytes.length, newBytes.length);
                this.nonce = new BigInteger(nonceBytes);
            }
        }
        this.nonce = nonce2;
    }

    public void setRequestTime(DVCSTime requestTime2) {
        if (this.initialInfo != null) {
            throw new IllegalStateException("cannot change request time in existing DVCSRequestInformation");
        }
        this.requestTime = requestTime2;
    }

    public void setRequester(GeneralName requester2) {
        setRequester(new GeneralNames(requester2));
    }

    public void setRequester(GeneralNames requester2) {
        this.requester = requester2;
    }

    public void setRequestPolicy(PolicyInformation requestPolicy2) {
        if (this.initialInfo != null) {
            throw new IllegalStateException("cannot change request policy in existing DVCSRequestInformation");
        }
        this.requestPolicy = requestPolicy2;
    }

    public void setDVCS(GeneralName dvcs2) {
        setDVCS(new GeneralNames(dvcs2));
    }

    public void setDVCS(GeneralNames dvcs2) {
        this.dvcs = dvcs2;
    }

    public void setDataLocations(GeneralName dataLocation) {
        setDataLocations(new GeneralNames(dataLocation));
    }

    public void setDataLocations(GeneralNames dataLocations2) {
        this.dataLocations = dataLocations2;
    }

    public void setExtensions(Extensions extensions2) {
        if (this.initialInfo != null) {
            throw new IllegalStateException("cannot change extensions in existing DVCSRequestInformation");
        }
        this.extensions = extensions2;
    }
}
