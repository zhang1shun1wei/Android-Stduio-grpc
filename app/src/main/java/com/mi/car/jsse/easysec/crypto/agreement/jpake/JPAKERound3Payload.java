package com.mi.car.jsse.easysec.crypto.agreement.jpake;

import java.math.BigInteger;

public class JPAKERound3Payload {
    private final BigInteger macTag;
    private final String participantId;

    public JPAKERound3Payload(String participantId2, BigInteger magTag) {
        this.participantId = participantId2;
        this.macTag = magTag;
    }

    public String getParticipantId() {
        return this.participantId;
    }

    public BigInteger getMacTag() {
        return this.macTag;
    }
}
