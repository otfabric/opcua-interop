package io.otfabric.opcuainterop;

import org.eclipse.milo.opcua.stack.core.types.builtin.*;
import org.eclipse.milo.opcua.stack.core.types.structured.SimpleAttributeOperand;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.*;

/** client alarms (docs/CLIENT_CONTRACT.md §4 `alarms`): select clauses, ConditionEntry, flags. */
public class AlarmsTest {

    @Test
    void selectClauses() {
        SimpleAttributeOperand[] s = ClientCommand.alarmSelectClauses();
        assertEquals(16, s.length);
        assertEquals(new NodeId(0, uint(2782)), s[15].getTypeDefinitionId());
        assertEquals(0, s[15].getBrowsePath().length);
        assertEquals(uint(1), s[15].getAttributeId());
        assertEquals(2, s[10].getBrowsePath().length);
        assertEquals("Id", s[10].getBrowsePath()[1].getName());
        assertEquals(new NodeId(0, uint(2915)), s[14].getTypeDefinitionId());
    }

    @Test
    void conditionEntry() {
        Variant[] f = {
            new Variant(ByteString.of(new byte[]{1, 2})),
            new Variant(new NodeId(0, uint(2915))),
            new Variant(new NodeId(1, "Alarms.Source")),
            new Variant("Alarms.Source"),
            new Variant(DateTime.now()),
            new Variant(LocalizedText.english("interop-alarm")),
            new Variant(ushort(500)),
            new Variant("InteropAlarm"),
            Variant.NULL_VALUE,
            new Variant(true),
            new Variant(true),
            new Variant(LocalizedText.english("")),
            new Variant(false),
            new Variant(new StatusCode(0x80340000L)),
            new Variant(true),
            new Variant(new NodeId(1, "Alarms.InteropAlarm")),
        };
        Map<String, Object> e = ClientCommand.conditionEntry(f);
        assertEquals(List.of("conditionId", "eventId", "eventType", "sourceNode", "sourceName",
            "conditionName", "time", "message", "severity", "retain", "enabled", "acked", "confirmed",
            "active", "comment"), List.copyOf(e.keySet()));
        assertEquals("ns=1;s=Alarms.InteropAlarm", e.get("conditionId"));
        assertEquals("AQI=", e.get("eventId"));
        assertEquals("i=2915", e.get("eventType"));
        assertEquals(500, e.get("severity"));
        assertEquals("interop-alarm", e.get("message"));
        assertEquals(Boolean.FALSE, e.get("acked"));
        assertNull(e.get("confirmed"));
        assertNull(ClientCommand.conditionEntry(new Variant[0]).get("conditionId"));
    }

    @Test
    void presenceFlags() {
        String[] a = {"--acknowledge", "--confirm", "false", "--add-comment"};
        assertTrue(ClientCommand.presenceFlag(a, "--acknowledge"));
        assertFalse(ClientCommand.presenceFlag(a, "--confirm"));
        assertTrue(ClientCommand.presenceFlag(a, "--add-comment"));
        assertFalse(ClientCommand.presenceFlag(new String[0], "--acknowledge"));
    }
}
