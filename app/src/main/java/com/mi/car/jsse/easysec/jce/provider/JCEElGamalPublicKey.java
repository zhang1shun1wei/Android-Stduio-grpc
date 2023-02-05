package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.oiw.ElGamalParameter;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.crypto.params.ElGamalPublicKeyParameters;
import com.mi.car.jsse.easysec.jcajce.provider.asymmetric.util.KeyUtil;
import com.mi.car.jsse.easysec.jce.interfaces.ElGamalPublicKey;
import com.mi.car.jsse.easysec.jce.spec.ElGamalParameterSpec;
import com.mi.car.jsse.easysec.jce.spec.ElGamalPublicKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

public class JCEElGamalPublicKey implements ElGamalPublicKey, DHPublicKey {
    static final long serialVersionUID = 8712728417091216948L;
    private ElGamalParameterSpec elSpec;
    private BigInteger y;

    JCEElGamalPublicKey(ElGamalPublicKeySpec spec) {
        this.y = spec.getY();
        this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
    }

    JCEElGamalPublicKey(DHPublicKeySpec spec) {
        this.y = spec.getY();
        this.elSpec = new ElGamalParameterSpec(spec.getP(), spec.getG());
    }

    JCEElGamalPublicKey(ElGamalPublicKey key) {
        this.y = key.getY();
        this.elSpec = key.getParameters();
    }

    JCEElGamalPublicKey(DHPublicKey key) {
        this.y = key.getY();
        this.elSpec = new ElGamalParameterSpec(key.getParams().getP(), key.getParams().getG());
    }

    JCEElGamalPublicKey(ElGamalPublicKeyParameters params) {
        this.y = params.getY();
        this.elSpec = new ElGamalParameterSpec(params.getParameters().getP(), params.getParameters().getG());
    }

    JCEElGamalPublicKey(BigInteger y2, ElGamalParameterSpec elSpec2) {
        this.y = y2;
        this.elSpec = elSpec2;
    }

    JCEElGamalPublicKey(SubjectPublicKeyInfo info) {
        ElGamalParameter params = ElGamalParameter.getInstance(info.getAlgorithm().getParameters());
        try {
            this.y = ((ASN1Integer) info.parsePublicKey()).getValue();
            this.elSpec = new ElGamalParameterSpec(params.getP(), params.getG());
        } catch (IOException e) {
            throw new IllegalArgumentException("invalid info structure in DSA public key");
        }
    }

    public String getAlgorithm() {
        return "ElGamal";
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(this.elSpec.getP(), this.elSpec.getG())), new ASN1Integer(this.y));
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.ElGamalKey
    public ElGamalParameterSpec getParameters() {
        return this.elSpec;
    }

    public DHParameterSpec getParams() {
        return new DHParameterSpec(this.elSpec.getP(), this.elSpec.getG());
    }

    @Override // com.mi.car.jsse.easysec.jce.interfaces.ElGamalPublicKey
    public BigInteger getY() {
        return this.y;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        this.y = (BigInteger) in.readObject();
        this.elSpec = new ElGamalParameterSpec((BigInteger) in.readObject(), (BigInteger) in.readObject());
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(getY());
        out.writeObject(this.elSpec.getP());
        out.writeObject(this.elSpec.getG());
    }
}
