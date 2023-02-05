package com.mi.car.jsse.easysec.jsse.provider;

import java.security.GeneralSecurityException;

interface EngineCreator {
    Object createInstance(Object obj) throws GeneralSecurityException;
}
