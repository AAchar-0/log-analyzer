package io.github.aachar0.loganalyzer;

import io.github.aachar0.loganalyzer.report.JsonReport;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class JsonReportTest {

    @Test
    void quoteEscapesWhatJsonRequires() {
        assertEquals("\"plain\"", JsonReport.quote("plain"));
        assertEquals("\"a\\\"b\"", JsonReport.quote("a\"b"));
        assertEquals("\"a\\\\b\"", JsonReport.quote("a\\b"));
        assertEquals("\"line1\\nline2\"", JsonReport.quote("line1\nline2"));
        assertEquals("\"caf\\u00e9\"", JsonReport.quote("caf\u00e9"));
    }

    @Test
    void htmlCharactersAreEscapedSoTheJsonIsHarmlessInsideAWebPage() {
        String json = JsonReport.quote("<script>alert(1)</script>&");
        assertFalse(json.contains("<"));
        assertFalse(json.contains(">"));
        assertFalse(json.contains("&"));
    }

    @Test
    void numbersNeverProduceInvalidJson() {
        assertEquals("0", JsonReport.number(Double.NaN));
        assertEquals("0", JsonReport.number(Double.POSITIVE_INFINITY));
        assertEquals("12.35", JsonReport.number(12.345678));
    }
}
