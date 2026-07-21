package io.otfabric.opcuainterop;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

public class FixtureLoaderTest {

    private static FixtureModel fixture;

    @BeforeAll
    static void loadFixture() throws Exception {
        fixture = FixtureLoader.load("../fixtures/baseline/fixture.json");
    }

    @Test
    void testFixtureNotNull() {
        assertNotNull(fixture);
        assertEquals("baseline", fixture.id);
    }

    @Test
    void testNamespace() {
        assertNotNull(fixture.namespaces);
        assertEquals(1, fixture.namespaces.size());
        assertEquals("urn:otfabric:opcua-interop:model", fixture.namespaces.get(0).uri);
    }

    @Test
    void testNodeCount() {
        assertNotNull(fixture.nodes);
        assertTrue(fixture.nodes.size() >= 30,
                "Expected >= 30 nodes but got " + fixture.nodes.size());
    }

    @Test
    void testScalarInt32Node() {
        FixtureModel.NodeDef int32Node = fixture.nodes.stream()
                .filter(n -> n.browseName != null && n.browseName.contains("Scalar.Int32"))
                .findFirst()
                .orElse(null);
        assertNotNull(int32Node, "Scalar.Int32 node not found");
        assertEquals("Int32", int32Node.dataType);
        assertNotNull(int32Node.value);
        assertEquals(-123456789, ((Number) int32Node.value).intValue());
    }

    @Test
    void testDynamicCounterNode() {
        boolean found = fixture.nodes.stream()
                .anyMatch(n -> n.browseName != null && n.browseName.contains("Dynamic.Counter"));
        assertTrue(found, "Dynamic.Counter node not found");
    }

    @Test
    void testCounterBehavior() {
        FixtureModel.BehaviorDef counter = fixture.behaviors.stream()
                .filter(b -> "counter".equals(b.kind))
                .findFirst()
                .orElse(null);
        assertNotNull(counter, "No counter behavior found");
        assertTrue(counter.intervalMs > 0, "intervalMs should be > 0");
    }

    @Test
    void testAccessReadWrite() {
        FixtureModel.NodeDef rw = fixture.nodes.stream()
                .filter(n -> n.browseName != null && n.browseName.contains("Access.ReadWrite"))
                .findFirst()
                .orElse(null);
        assertNotNull(rw, "Access.ReadWrite node not found");
        assertTrue(rw.accessLevel.contains("CurrentWrite"),
                "Expected CurrentWrite in accessLevel, got: " + rw.accessLevel);
    }

    @Test
    void testMethodsAdd() {
        FixtureModel.NodeDef addMethod = fixture.nodes.stream()
                .filter(n -> n.browseName != null && n.browseName.contains("Methods.Add"))
                .findFirst()
                .orElse(null);
        assertNotNull(addMethod, "Methods.Add node not found");
        assertNotNull(addMethod.inputArguments);
        assertEquals(2, addMethod.inputArguments.size(),
                "Expected 2 input arguments for Methods.Add");
    }
}
