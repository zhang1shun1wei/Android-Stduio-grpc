package com.mi.car.jsse.easysec.i18n;

import java.io.UnsupportedEncodingException;
import java.util.Locale;
import java.util.TimeZone;

public class TextBundle extends LocalizedMessage {
    public static final String TEXT_ENTRY = "text";

    public TextBundle(String resource, String id) throws NullPointerException {
        super(resource, id);
    }

    public TextBundle(String resource, String id, String encoding) throws NullPointerException, UnsupportedEncodingException {
        super(resource, id, encoding);
    }

    public TextBundle(String resource, String id, Object[] arguments) throws NullPointerException {
        super(resource, id, arguments);
    }

    public TextBundle(String resource, String id, String encoding, Object[] arguments) throws NullPointerException, UnsupportedEncodingException {
        super(resource, id, encoding, arguments);
    }

    public String getText(Locale loc, TimeZone timezone) throws MissingEntryException {
        return getEntry(TEXT_ENTRY, loc, timezone);
    }

    public String getText(Locale loc) throws MissingEntryException {
        return getEntry(TEXT_ENTRY, loc, TimeZone.getDefault());
    }
}
