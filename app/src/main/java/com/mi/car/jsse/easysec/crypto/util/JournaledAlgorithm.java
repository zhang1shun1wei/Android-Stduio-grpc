package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.util.Encodable;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.SecureRandom;

public class JournaledAlgorithm implements Encodable, Serializable {
    private transient AlgorithmIdentifier algID;
    private transient JournalingSecureRandom journaling;

    public JournaledAlgorithm(AlgorithmIdentifier aid, JournalingSecureRandom journaling2) {
        if (aid == null) {
            throw new NullPointerException("AlgorithmIdentifier passed to JournaledAlgorithm is null");
        } else if (journaling2 == null) {
            throw new NullPointerException("JournalingSecureRandom passed to JournaledAlgorithm is null");
        } else {
            this.journaling = journaling2;
            this.algID = aid;
        }
    }

    public JournaledAlgorithm(byte[] encoding) {
        this(encoding, CryptoServicesRegistrar.getSecureRandom());
    }

    public JournaledAlgorithm(byte[] encoding, SecureRandom random) {
        if (encoding == null) {
            throw new NullPointerException("encoding passed to JournaledAlgorithm is null");
        } else if (random == null) {
            throw new NullPointerException("random passed to JournaledAlgorithm is null");
        } else {
            initFromEncoding(encoding, random);
        }
    }

    private void initFromEncoding(byte[] encoding, SecureRandom random) {
        ASN1Sequence seq = ASN1Sequence.getInstance(encoding);
        this.algID = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.journaling = new JournalingSecureRandom(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets(), random);
    }

    public JournalingSecureRandom getJournalingSecureRandom() {
        return this.journaling;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return this.algID;
    }

    public void storeState(File tempfile) throws IOException {
        if (tempfile == null) {
            throw new NullPointerException("file for storage is null in JournaledAlgorithm");
        }
        FileOutputStream fOut = new FileOutputStream(tempfile);
        try {
            storeState(fOut);
        } finally {
            fOut.close();
        }
    }

    public void storeState(OutputStream out) throws IOException {
        if (out == null) {
            throw new NullPointerException("output stream for storage is null in JournaledAlgorithm");
        }
        out.write(getEncoded());
    }

    public static JournaledAlgorithm getState(InputStream stateIn, SecureRandom random) throws IOException, ClassNotFoundException {
        if (stateIn == null) {
            throw new NullPointerException("stream for loading is null in JournaledAlgorithm");
        }
        InputStream fIn = new BufferedInputStream(stateIn);
        try {
            return new JournaledAlgorithm(Streams.readAll(fIn), random);
        } finally {
            fIn.close();
        }
    }

    public static JournaledAlgorithm getState(File tempfile, SecureRandom random) throws IOException, ClassNotFoundException {
        if (tempfile == null) {
            throw new NullPointerException("File for loading is null in JournaledAlgorithm");
        }
        InputStream fIn = new BufferedInputStream(new FileInputStream(tempfile));
        try {
            return new JournaledAlgorithm(Streams.readAll(fIn), random);
        } finally {
            fIn.close();
        }
    }

    @Override // com.mi.car.jsse.easysec.util.Encodable
    public byte[] getEncoded() throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.algID);
        v.add(new DEROctetString(this.journaling.getFullTranscript()));
        return new DERSequence(v).getEncoded();
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        initFromEncoding((byte[]) in.readObject(), CryptoServicesRegistrar.getSecureRandom());
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeObject(getEncoded());
    }
}
