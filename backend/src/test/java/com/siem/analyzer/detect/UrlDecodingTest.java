package com.siem.analyzer.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class UrlDecodingTest {

    @Test
    void decodesPercentEscapesAndPlus() {
        assertEquals("/a?q=' OR 1=1", UrlDecoding.decode("/a?q=%27+OR+1%3d1"));
    }

    @Test
    void decodesMultiByteCharacters() {
        assertEquals("/café", UrlDecoding.decode("/caf%C3%A9"));
        assertEquals("/café/ünï", UrlDecoding.decode("/café/%C3%BCn%C3%AF"));
    }

    @Test
    void doubleAndTripleEncodingIsUndone() {
        assertEquals("'", UrlDecoding.decode("%2527"));
        assertEquals("'", UrlDecoding.decode("%252527"));
    }

    @Test
    void anEncodedPlusIsNotASpace() {
        assertEquals("a+b", UrlDecoding.decode("a%2Bb"));
    }

    @Test
    void malformedEscapesAreKept() {
        assertEquals("100% %zz %4", UrlDecoding.decode("100% %zz %4"));
        // Arabic-Indic digits are digits to Character.digit, but not hex to a URL.
        assertEquals("%١٢", UrlDecoding.decode("%١٢"));
    }

    @Test
    void invalidUtf8BecomesReplacementCharacters() {
        assertEquals("/a�b", UrlDecoding.decode("/a%FFb"));
    }

    @Test
    void nullStaysNull() {
        assertNull(UrlDecoding.decode(null));
    }
}
