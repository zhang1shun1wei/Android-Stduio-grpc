package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.pkcs.DHParameter;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.asn1.x9.DHDomainParameters;
import com.mi.car.jsse.easysec.asn1.x9.X9ObjectIdentifiers;
import com.mi.car.jsse.easysec.crypto.params.DHPublicKeyParameters;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.KeyUtil;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

public class JCEDHPublicKey implements DHPublicKey {
    static final long serialVersionUID = -216691575254424324L;
    private DHParameterSpec dhSpec;
    private SubjectPublicKeyInfo info;
    private BigInteger y;

    JCEDHPublicKey(DHPublicKeySpec spec) {
        this.y = spec.getY();
        this.dhSpec = new DHParameterSpec(spec.getP(), spec.getG());
    }

    JCEDHPublicKey(DHPublicKey key) {
        this.y = key.getY();
        this.dhSpec = key.getParams();
    }

    JCEDHPublicKey(DHPublicKeyParameters params) {
        this.y = params.getY();
        this.dhSpec = new DHParameterSpec(params.getParameters().getP(), params.getParameters().getG(), params.getParameters().getL());
    }

    JCEDHPublicKey(BigInteger y2, DHParameterSpec dhSpec2) {
        this.y = y2;
        this.dhSpec = dhSpec2;
    }

    JCEDHPublicKey(SubjectPublicKeyInfo info2) {
        this.info = info2;
        try {
            this.y = ((ASN1Integer) info2.parsePublicKey()).getValue();
            ASN1Sequence seq = ASN1Sequence.getInstance(info2.getAlgorithmId().getParameters());
            ASN1ObjectIdentifier id = info2.getAlgorithmId().getAlgorithm();
            if (id.equals((ASN1Primitive) PKCSObjectIdentifiers.dhKeyAgreement) || isPKCSParam(seq)) {
                DHParameter params = DHParameter.getInstance(seq);
                if (params.getL() != null) {
                    this.dhSpec = new DHParameterSpec(params.getP(), params.getG(), params.getL().intValue());
                } else {
                    this.dhSpec = new DHParameterSpec(params.getP(), params.getG());
                }
            } else if (id.equals((ASN1Primitive) X9ObjectIdentifiers.dhpublicnumber)) {
                DHDomainParameters params2 = DHDomainParameters.getInstance(seq);
                this.dhSpec = new DHParameterSpec(params2.getP().getValue(), params2.getG().getValue());
            } else {
                throw new IllegalArgumentException("unknown algorithm type: " + id);
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("invalid info structure in DH public key");
        }
    }

    public String getAlgorithm() {
        return "DH";
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        if (this.info != null) {
            return KeyUtil.getEncodedSubjectPublicKeyInfo(this.info);
        }
        return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement, new DHParameter(this.dhSpec.getP(), this.dhSpec.getG(), this.dhSpec.getL())), new ASN1Integer(this.y));
    }

    public DHParameterSpec getParams() {
        return this.dhSpec;
    }

    public BigInteger getY() {
        return this.y;
    }

    private boolean isPKCSParam(ASN1Sequence seq) {
        if (seq.size() == 2) {
            return true;
        }
        if (seq.size() > 3) {
            return false;
        }
        return ASN1Integer.getInstance(seq.getObjectAt(2)).getValue().compareTo(BigInteger.valueOf((long) ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().bitLength())) <= 0;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        this.y = (BigInteger) in.readObject();
        this.dhSpec = new DHParameterSpec((BigInteger) in.readObject(), (BigInteger) in.readObject(), in.readInt());
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(getY());
        out.writeObject(this.dhSpec.getP());
        out.writeObject(this.dhSpec.getG());
        out.writeInt(this.dhSpec.getL());
    }
}
