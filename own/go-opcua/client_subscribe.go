// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
)

func subscribeCommand(fs *flag.FlagSet) command {
	node := fs.String("node", "", "node to monitor")
	publishing := fs.Int64("publishing-interval-ms", 500, "publishing interval")
	sampling := fs.Int64("sampling-interval-ms", 100, "sampling interval")
	count := fs.Int("notifications", 5, "notifications to collect")
	timeoutMS := fs.Int64("timeout-ms", 10000, "command timeout")
	queueSize := fs.Uint("queue-size", 1, "queue size")
	discardOldest := fs.String("discard-oldest", "true", "queue overflow policy")
	timestamps := fs.String("timestamps", "Both", "TimestampsToReturn")
	absolute := fs.Float64("deadband-absolute", 0, "absolute deadband")
	percent := fs.Float64("deadband-percent", 0, "percent deadband")
	trigger := fs.String("trigger", "StatusValue", "DataChangeFilter trigger")
	set := map[string]bool{}
	var ref nodeRef
	var ts ua.TimestampsToReturn
	var triggerValue ua.DataChangeTrigger
	return command{
		validate: func() (err error) {
			fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
			if set["deadband-absolute"] && set["deadband-percent"] {
				return errors.New("--deadband-absolute and --deadband-percent exclude each other")
			}
			var ok bool
			if ts, ok = map[string]ua.TimestampsToReturn{"Source": ua.TimestampsToReturnSource, "Server": ua.TimestampsToReturnServer, "Both": ua.TimestampsToReturnBoth, "Neither": ua.TimestampsToReturnNeither}[*timestamps]; !ok {
				return errors.New("--timestamps: " + *timestamps)
			}
			if triggerValue, ok = map[string]ua.DataChangeTrigger{"Status": ua.DataChangeTriggerStatus, "StatusValue": ua.DataChangeTriggerStatusValue, "StatusValueTimestamp": ua.DataChangeTriggerStatusValueTimestamp}[*trigger]; !ok {
				return errors.New("--trigger: " + *trigger)
			}
			ref, err = parseNodeRef(*node)
			return err
		},
		run: func(requestCtx context.Context, c *opcua.Client) outcome {
			nodeID, failed := resolve(requestCtx, c, ref)
			if failed != nil {
				return *failed
			}
			notify := make(chan *opcua.PublishNotificationData, 64)
			sub, err := c.Subscribe(requestCtx, &opcua.SubscriptionParameters{Interval: time.Duration(*publishing) * time.Millisecond}, notify)
			if err != nil {
				return classify(err)
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = sub.Cancel(ctx)
			}()

			// A filter only when one was asked for: the result then says so (§4).
			var filter *ua.DataChangeFilter
			deadbandName := "None"
			if set["deadband-absolute"] || set["deadband-percent"] || set["trigger"] {
				filter = &ua.DataChangeFilter{Trigger: triggerValue, DeadbandType: uint32(ua.DeadbandTypeNone)}
				switch {
				case set["deadband-absolute"]:
					filter.DeadbandType, filter.DeadbandValue, deadbandName = uint32(ua.DeadbandTypeAbsolute), *absolute, "Absolute"
				case set["deadband-percent"]:
					filter.DeadbandType, filter.DeadbandValue, deadbandName = uint32(ua.DeadbandTypePercent), *percent, "Percent"
				}
			}
			params := &ua.MonitoringParameters{
				ClientHandle: 1, SamplingInterval: float64(*sampling),
				QueueSize: uint32(*queueSize), DiscardOldest: *discardOldest != "false",
			}
			if filter != nil {
				params.Filter = ua.NewExtensionObject(filter)
			}
			resp, err := sub.Monitor(requestCtx, ts, &ua.MonitoredItemCreateRequest{
				ItemToMonitor:       &ua.ReadValueID{NodeID: nodeID, AttributeID: ua.AttributeIDValue},
				MonitoringMode:      ua.MonitoringModeReporting,
				RequestedParameters: params,
			})
			if err != nil {
				return classify(err)
			}
			item := resp.Results[0]

			result := map[string]any{
				"nodeId":                    nodeIDString(nodeID),
				"subscriptionId":            sub.SubscriptionID,
				"revisedPublishingInterval": float64(sub.RevisedPublishingInterval / time.Millisecond),
				"revisedLifetimeCount":      sub.RevisedLifetimeCount,
				"revisedMaxKeepAliveCount":  sub.RevisedMaxKeepAliveCount,
				"monitoredItemStatusCode":   statusOf(item.StatusCode),
			}
			if filter != nil {
				result["monitoredItemId"] = item.MonitoredItemID
				result["revisedSamplingInterval"] = item.RevisedSamplingInterval
				result["revisedQueueSize"] = item.RevisedQueueSize
				result["filter"] = map[string]any{"trigger": *trigger, "deadbandType": deadbandName, "deadbandValue": filter.DeadbandValue}
				result["filterResult"] = nil
				if item.FilterResult != nil && item.FilterResult.TypeID != nil {
					result["filterResult"] = map[string]any{"typeId": item.FilterResult.TypeID.String()}
				}
			}
			result["notifications"] = []any{}
			results := []any{result}
			if !isGood(item.StatusCode) {
				return serviceBad(item.StatusCode, results)
			}

			notifications, res := collect(notify, *count, time.Duration(*timeoutMS)*time.Millisecond)
			result["notifications"] = notifications
			res.results = results
			return res
		},
	}
}

// collect reads data-change notifications until there are enough, or the timeout
// has passed. The sequence number is the position in the result: go-opcua does not
// hand out the one of the NotificationMessage.
func collect(notify <-chan *opcua.PublishNotificationData, count int, timeout time.Duration) ([]any, outcome) {
	deadline := time.After(timeout)
	notifications := []any{}
	for len(notifications) < count {
		select {
		case msg := <-notify:
			if msg.Error != nil {
				return notifications, classify(msg.Error)
			}
			change, ok := msg.Value.(*ua.DataChangeNotification)
			if !ok {
				continue
			}
			for _, item := range change.MonitoredItems {
				if len(notifications) == count {
					break
				}
				notifications = append(notifications, notification(len(notifications)+1, item.Value))
			}
		case <-deadline:
			res := failure(exitTimeout, "timeout", fmt.Sprintf("%d of %d notifications after %v", len(notifications), count, timeout), ua.StatusBadTimeout)
			return notifications, res
		}
	}
	return notifications, outcome{status: ua.StatusOK}
}

func notification(sequence int, dv *ua.DataValue) map[string]any {
	n := map[string]any{"sequenceNumber": sequence, "statusCode": statusOf(dv.Status), "value": encodeValue(dv.Value)}
	if dv.Value != nil && dv.Value.Value() != nil {
		n["dataType"] = typeName(uint32(dv.Value.Type()))
		n["builtInType"] = int(dv.Value.Type())
	}
	if !dv.SourceTimestamp.IsZero() {
		n["sourceTimestamp"] = timeString(dv.SourceTimestamp)
	}
	if !dv.ServerTimestamp.IsZero() {
		n["serverTimestamp"] = timeString(dv.ServerTimestamp)
	}
	return n
}
