package com.mi.car.jsse.easysec.crypto.agreement.jpake;

import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class JPAKERound2Payload {
    private final BigInteger a;
    private final BigInteger[] knowledgeProofForX2s;
    private final String participantId;

    public JPAKERound2Payload(String participantId2, BigInteger a2, BigInteger[] knowledgeProofForX2s2) {
        JPAKEUtil.validateNotNull(participantId2, "participantId");
        JPAKEUtil.validateNotNull(a2, "a");
        JPAKEUtil.validateNotNull(knowledgeProofForX2s2, "knowledgeProofForX2s");
        this.participantId = participantId2;
        this.a = a2;
        this.knowledgeProofForX2s = Arrays.copyOf(knowledgeProofForX2s2, knowledgeProofForX2s2.length);
    }

    public String getParticipantId() {
        return this.participantId;
    }

    public BigInteger getA() {
        return this.a;
    }

    public BigInteger[] getKnowledgeProofForX2s() {
        return Arrays.copyOf(this.knowledgeProofForX2s, this.knowledgeProofForX2s.length);
    }
}
