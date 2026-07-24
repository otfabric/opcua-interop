package org.eclipse.milo.opcua.sdk.client.subscriptions;

import java.util.List;
import java.util.Objects;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.CreateMonitoredItemsResponse;
import org.eclipse.milo.opcua.stack.core.types.structured.MonitoredItemCreateResult;

/**
 * Package-local helper: Milo's {@link OpcUaSubscription#createMonitoredItems()}
 * hardcodes {@link TimestampsToReturn#Both}. Interop adapters need to pass the
 * requested timestamps through CreateMonitoredItems.
 */
public final class CreateMonitoredItemsWithTimestamps {
    private CreateMonitoredItemsWithTimestamps() {}

    public static StatusCode create(
            OpcUaClient client,
            OpcUaSubscription subscription,
            OpcUaMonitoredItem item,
            TimestampsToReturn timestamps) throws UaException {
        UInteger subId = subscription.getSubscriptionId()
            .orElseThrow(() -> new UaException(StatusCode.BAD.getValue(), "subscription not created"));
        CreateMonitoredItemsResponse response = client.createMonitoredItems(
            subId,
            timestamps,
            List.of(item.newCreateRequest()));
        MonitoredItemCreateResult[] results = Objects.requireNonNull(response.getResults());
        if (results.length == 0) {
            throw new UaException(StatusCode.BAD.getValue(), "empty CreateMonitoredItems results");
        }
        item.applyCreateResult(results[0]);
        return results[0].getStatusCode() != null ? results[0].getStatusCode() : StatusCode.GOOD;
    }
}
