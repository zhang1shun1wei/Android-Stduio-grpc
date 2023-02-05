package com.mi.car.jsse.easysec.crypto.commitments;

import com.mi.car.jsse.easysec.crypto.Commitment;
import com.mi.car.jsse.easysec.crypto.Committer;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.util.Arrays;
import java.security.SecureRandom;

public class GeneralHashCommitter implements Committer {
    private final int byteLength;
    private final Digest digest;
    private final SecureRandom random;

    public GeneralHashCommitter(ExtendedDigest digest2, SecureRandom random2) {
        this.digest = digest2;
        this.byteLength = digest2.getByteLength();
        this.random = random2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Committer
    public Commitment commit(byte[] message) {
        if (message.length > this.byteLength / 2) {
            throw new DataLengthException("Message to be committed to too large for digest.");
        }
        byte[] w = new byte[(this.byteLength - message.length)];
        this.random.nextBytes(w);
        return new Commitment(w, calculateCommitment(w, message));
    }

    @Override // com.mi.car.jsse.easysec.crypto.Committer
    public boolean isRevealed(Commitment commitment, byte[] message) {
        if (message.length + commitment.getSecret().length != this.byteLength) {
            throw new DataLengthException("Message and witness secret lengths do not match.");
        }
        return Arrays.constantTimeAreEqual(commitment.getCommitment(), calculateCommitment(commitment.getSecret(), message));
    }

    private byte[] calculateCommitment(byte[] w, byte[] message) {
        byte[] commitment = new byte[this.digest.getDigestSize()];
        this.digest.update(w, 0, w.length);
        this.digest.update(message, 0, message.length);
        this.digest.update((byte) (message.length >>> 8));
        this.digest.update((byte) message.length);
        this.digest.doFinal(commitment, 0);
        return commitment;
    }
}
