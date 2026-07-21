package io.otfabric.opcuainterop;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;

public class FixtureLoader {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    public static FixtureModel load(String path) throws IOException {
        return MAPPER.readValue(new File(path), FixtureModel.class);
    }
}
