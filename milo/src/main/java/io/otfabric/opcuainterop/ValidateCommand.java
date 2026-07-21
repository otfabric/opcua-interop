package io.otfabric.opcuainterop;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

public class ValidateCommand {

    public static int run(String[] args) {
        String fixturePath = null;
        for (int i = 0; i < args.length - 1; i++) {
            if ("--fixture".equals(args[i])) {
                fixturePath = args[i + 1];
            }
        }
        if (fixturePath == null && args.length > 0 && !args[0].startsWith("--")) {
            fixturePath = args[0];
        }
        if (fixturePath == null) {
            System.err.println("usage: validate-fixture --fixture <path>");
            return 1;
        }

        List<String> errors = new ArrayList<>();
        try {
            FixtureModel fixture = FixtureLoader.load(fixturePath);
            if (fixture.schemaVersion == null) errors.add("missing schemaVersion");
            if (fixture.id == null)            errors.add("missing id");
            if (fixture.server == null)        errors.add("missing server");
            if (fixture.endpoint == null)      errors.add("missing endpoint");
            if (fixture.namespaces == null)    errors.add("missing namespaces");
        } catch (Exception e) {
            errors.add(e.getMessage());
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            if (errors.isEmpty()) {
                System.out.println("{\"valid\":true}");
                return 0;
            } else {
                System.out.println("{\"valid\":false,\"errors\":" + mapper.writeValueAsString(errors) + "}");
                return 1;
            }
        } catch (Exception e) {
            System.out.println("{\"valid\":false,\"errors\":[\"serialization error\"]}");
            return 1;
        }
    }
}
