package com.mi.car.jsse.easysec.crypto.agreement.jpake;

import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class JPAKERound1Payload {
    private final BigInteger gx1;
    private final BigInteger gx2;
    private final BigInteger[] knowledgeProofForX1;
    private final BigInteger[] knowledgeProofForX2;
    private final String participantId;

    public JPAKERound1Payload(String participantId2, BigInteger gx12, BigInteger gx22, BigInteger[] knowledgeProofForX12, BigInteger[] knowledgeProofForX22) {
        JPAKEUtil.validateNotNull(participantId2, "participantId");
        JPAKEUtil.validateNotNull(gx12, "gx1");
        JPAKEUtil.validateNotNull(gx22, "gx2");
        JPAKEUtil.validateNotNull(knowledgeProofForX12, "knowledgeProofForX1");
        JPAKEUtil.validateNotNull(knowledgeProofForX22, "knowledgeProofForX2");
        this.participantId = participantId2;
        this.gx1 = gx12;
        this.gx2 = gx22;
        this.knowledgeProofForX1 = Arrays.copyOf(knowledgeProofForX12, knowledgeProofForX12.length);
        this.knowledgeProofForX2 = Arrays.copyOf(knowledgeProofForX22, knowledgeProofForX22.length);
    }

    public String getParticipantId() {
        return this.participantId;
    }

    public BigInteger getGx1() {
        return this.gx1;
    }

    public BigInteger getGx2() {
        return this.gx2;
    }

    public BigInteger[] getKnowledgeProofForX1() {
        return Arrays.copyOf(this.knowledgeProofForX1, this.knowledgeProofForX1.length);
    }

    public BigInteger[] getKnowledgeProofForX2() {
        return Arrays.copyOf(this.knowledgeProofForX2, this.knowledgeProofForX2.length);
    }
}
