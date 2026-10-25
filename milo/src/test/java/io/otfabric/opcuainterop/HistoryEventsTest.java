package io.otfabric.opcuainterop;

import com.fasterxml.jackson.databind.JsonNode;
import org.eclipse.milo.opcua.stack.core.encoding.DefaultEncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.types.builtin.*;
import org.eclipse.milo.opcua.stack.core.types.enumerated.FilterOperator;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PerformUpdateType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.*;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.*;

/** client history-read-events / history-update-events: select paths, WhereClause, --event JSON. */
public class HistoryEventsTest {

    private static final EncodingContext CTX = DefaultEncodingContext.INSTANCE;

    @Test
    void selectPaths() throws Exception {
        QualifiedName[] p = HistoryEventsCommand.browsePath("AckedState/Id");
        assertEquals(2, p.length);
        assertEquals(new QualifiedName(0, "AckedState"), p[0]);
        assertEquals(new QualifiedName(0, "Id"), p[1]);
        p = HistoryEventsCommand.browsePath("2:Custom/Value");
        assertEquals(new QualifiedName(2, "Custom"), p[0]);
        assertThrows(ClientCommand.InputException.class, () -> HistoryEventsCommand.browsePath("A//B"));
        assertThrows(ClientCommand.InputException.class, () -> HistoryEventsCommand.browsePath(""));

        SimpleAttributeOperand[] s = HistoryEventsCommand.selectClauses(HistoryEventsCommand.DEFAULT_SELECT);
        assertEquals(8, s.length);
        assertEquals(new NodeId(0, uint(2041)), s[0].getTypeDefinitionId());
        assertEquals(uint(13), s[0].getAttributeId());
        assertEquals("ReceiveTime", s[5].getBrowsePath()[0].getName());
    }

    private static FilterOperator op(ContentFilter f, int i) {
        return f.getElements()[i].getFilterOperator();
    }

    @Test
    void whereClause() {
        assertEquals(0, HistoryEventsCommand.whereClause(CTX, null, null).getElements().length);

        ContentFilter f = HistoryEventsCommand.whereClause(CTX, new NodeId(0, uint(2130)), null);
        assertEquals(1, f.getElements().length);
        assertEquals(FilterOperator.OfType, op(f, 0));
        LiteralOperand lit = (LiteralOperand) f.getElements()[0].getFilterOperands()[0].decode(CTX);
        assertEquals(new NodeId(0, uint(2130)), lit.getValue().getValue());

        f = HistoryEventsCommand.whereClause(CTX, null, 300);
        assertEquals(1, f.getElements().length);
        assertEquals(FilterOperator.GreaterThanOrEqual, op(f, 0));
        lit = (LiteralOperand) f.getElements()[0].getFilterOperands()[1].decode(CTX);
        assertEquals(ushort(300), lit.getValue().getValue());

        f = HistoryEventsCommand.whereClause(CTX, new NodeId(0, uint(2130)), 300);
        assertEquals(3, f.getElements().length);
        assertEquals(FilterOperator.And, op(f, 0), "element 0 is the root");
        assertEquals(FilterOperator.OfType, op(f, 1));
        assertEquals(FilterOperator.GreaterThanOrEqual, op(f, 2));
        ElementOperand a = (ElementOperand) f.getElements()[0].getFilterOperands()[0].decode(CTX);
        ElementOperand b = (ElementOperand) f.getElements()[0].getFilterOperands()[1].decode(CTX);
        assertEquals(uint(1), a.getIndex());
        assertEquals(uint(2), b.getIndex());
    }

    @Test
    void performAndTimestamps() throws Exception {
        assertEquals(PerformUpdateType.Insert, HistoryEventsCommand.perform("insert"));
        assertEquals(PerformUpdateType.Remove, HistoryEventsCommand.perform("Delete"));
        assertEquals("Delete", HistoryEventsCommand.performName(PerformUpdateType.Remove));
        assertEquals("Update", HistoryEventsCommand.performName(PerformUpdateType.Update));
        assertThrows(ClientCommand.InputException.class, () -> HistoryEventsCommand.perform("upsert"));
        assertEquals(TimestampsToReturn.Neither, HistoryEventsCommand.timestamps("neither"));
        assertEquals(TimestampsToReturn.Source, HistoryEventsCommand.timestamps("Source"));
        assertEquals(TimestampsToReturn.Both, HistoryEventsCommand.timestamps(null));
        assertThrows(ClientCommand.InputException.class, () -> HistoryEventsCommand.timestamps("all"));
    }

    @Test
    void eventJson() throws Exception {
        String ev = "{\"EventId\":{\"type\":\"ByteString\",\"value\":\"aGlzdC1ldnQtNQ==\"},"
            + "\"Time\":{\"type\":\"DateTime\",\"value\":\"2026-07-24T10:00:25.1234567Z\"},"
            + "\"Severity\":{\"type\":\"UInt16\",\"value\":700},"
            + "\"Message\":{\"type\":\"LocalizedText\",\"value\":{\"text\":\"x\"}},"
            + "\"EventType\":{\"type\":\"NodeId\",\"value\":\"i=2041\"},"
            + "\"SourceName\":{\"type\":\"String\",\"value\":\"History.Events\"},"
            + "\"Plain\":\"text\"}";
        List<JsonNode> events = HistoryEventsCommand.parseEvents(List.of(ev));
        List<String> select = HistoryEventsCommand.updateSelect(List.of(), events);
        assertEquals(List.of("EventId", "Time", "Severity", "Message", "EventType", "SourceName", "Plain"), select);

        List<String> withMissing = List.of("EventId", "Severity", "ReceiveTime");
        HistoryEventFieldList fl = HistoryEventsCommand.eventFieldList(withMissing, events.get(0), NodeIdParser::parse);
        Variant[] f = fl.getEventFields();
        assertEquals("hist-evt-5", new String(((ByteString) f[0].getValue()).bytes(), StandardCharsets.US_ASCII));
        assertEquals(ushort(700), f[1].getValue());
        assertTrue(f[2].isNull(), "a key the event lacks is a null Variant");

        fl = HistoryEventsCommand.eventFieldList(select, events.get(0), NodeIdParser::parse);
        f = fl.getEventFields();
        DateTime t = (DateTime) f[1].getValue();
        assertEquals("2026-07-24T10:00:25.123456700Z", t.getJavaInstant().toString());
        assertEquals(new LocalizedText(null, "x"), f[3].getValue());
        assertEquals(new NodeId(0, uint(2041)), f[4].getValue());
        assertEquals("History.Events", f[5].getValue());
        assertEquals("text", f[6].getValue());

        assertThrows(ClientCommand.InputException.class, () -> HistoryEventsCommand.parseEvents(List.of("[1]")));
        assertThrows(ClientCommand.InputException.class, () -> HistoryEventsCommand.parseEvents(List.of("{")));
        JsonNode bad = HistoryEventsCommand.parseEvents(List.of("{\"X\":{\"type\":\"Nope\",\"value\":1}}")).get(0);
        assertThrows(ClientCommand.InputException.class,
            () -> HistoryEventsCommand.eventFieldList(List.of("X"), bad, NodeIdParser::parse));
    }

    @Test
    void eventsJson() {
        HistoryEventFieldList ev = new HistoryEventFieldList(new Variant[]{
            new Variant(ByteString.of("hist-evt-0".getBytes(StandardCharsets.US_ASCII))),
            new Variant(LocalizedText.english("history-event-0")),
            Variant.NULL_VALUE,
            new Variant(new StatusCode(0x809B0000L)),
        });
        List<Map<String, Object>> out = HistoryEventsCommand.eventsJson(
            List.of("EventId", "Message", "SourceNode", "Custom", "Missing"), new HistoryEventFieldList[]{ ev });
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> fields = (List<Map<String, Object>>) out.get(0).get("fields");
        assertEquals(5, fields.size());
        assertEquals("aGlzdC1ldnQtMA==", fields.get(0).get("value"));
        assertEquals(15, fields.get(0).get("builtInType"));
        assertEquals("LocalizedText", fields.get(1).get("dataType"));
        assertEquals("Null", fields.get(2).get("dataType"));
        assertEquals(0, fields.get(2).get("builtInType"));
        assertEquals("StatusCode", fields.get(3).get("dataType"));
        assertEquals("Null", fields.get(4).get("dataType"), "fewer fields than select clauses");
    }
}
