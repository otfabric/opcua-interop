// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

// discoverFlags are the flags of `pubsub-discover` (§14.13).
type discoverFlags struct {
	url, typ, writerIDs, publisherID string
	timeoutMS                        int
	writers                          []uint16
	publisher                        *uint16
}

func discoverCommand(fs *flag.FlagSet) command {
	f := &discoverFlags{}
	fs.StringVar(&f.url, "url", "", "opc.udp://host:port")
	fs.StringVar(&f.typ, "type", "DataSetMetaData", "DataSetMetaData or DataSetWriterConfiguration")
	fs.StringVar(&f.writerIDs, "writer-ids", "", "DataSetWriterIds of the probe")
	fs.StringVar(&f.publisherID, "publisher-id", "", "PublisherId of the probing connection")
	fs.IntVar(&f.timeoutMS, "timeout-ms", 3000, "time to collect announcements")
	return command{
		offline:  func() bool { return true },
		validate: f.validate,
		local:    f.run,
		budget:   func() time.Duration { return time.Duration(f.timeoutMS)*time.Millisecond + 5*time.Second },
	}
}

func (f *discoverFlags) validate() error {
	if f.url == "" {
		return errors.New("--url is required")
	}
	if !strings.HasPrefix(f.url, "opc.udp://") {
		return errors.New("--url: " + f.url + ": want opc.udp://")
	}
	if f.typ != "DataSetMetaData" && f.typ != "DataSetWriterConfiguration" {
		return errors.New("--type: " + f.typ)
	}
	if f.timeoutMS <= 0 {
		return errors.New("--timeout-ms: must be positive")
	}
	if f.writerIDs != "" {
		for _, word := range strings.Split(f.writerIDs, ",") {
			id, err := strconv.ParseUint(word, 10, 16)
			if err != nil {
				return fmt.Errorf("--writer-ids: %w", err)
			}
			f.writers = append(f.writers, uint16(id))
		}
	}
	if f.publisherID != "" {
		id, err := strconv.ParseUint(f.publisherID, 10, 16)
		if err != nil {
			return fmt.Errorf("--publisher-id: %w", err)
		}
		f.publisher = ptr(uint16(id))
	}
	return nil
}

// socket is bound to the port of the URL and joins its group when it is one.
func (f *discoverFlags) socket() (*net.UDPConn, *net.UDPAddr, error) {
	u, err := url.Parse(f.url)
	if err != nil {
		return nil, nil, err
	}
	dest, err := net.ResolveUDPAddr("udp4", u.Host)
	if err != nil {
		return nil, nil, err
	}
	if dest.IP.IsMulticast() {
		sock, err := net.ListenMulticastUDP("udp4", nil, dest)
		return sock, dest, err
	}
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{})
	return sock, dest, err
}

func (f *discoverFlags) run() outcome {
	sock, dest, err := f.socket()
	if err != nil {
		return failure(exitConnect, "connection", err.Error(), ua.StatusBadCommunicationError)
	}
	defer sock.Close()
	info, want := message.InformationDataSetMetaData, message.DiscoveryDataSetMetaData
	if f.typ == "DataSetWriterConfiguration" {
		info, want = message.InformationDataSetWriterConfig, message.DiscoveryDataSetWriterConfig
	}
	probe := &message.NetworkMessage{Type: message.NetworkMessageDiscoveryRequest, Request: &message.DiscoveryRequest{
		ProbeType: message.ProbePublisherInformation, InformationType: info, DataSetWriterIDs: f.writers, Layout: message.DiscoveryLayoutDotNet}}
	if f.publisher != nil {
		probe.PublisherID = message.NewPublisherID(message.PublisherIDUInt16, uint64(*f.publisher))
		probe.UADPMask |= ua.UADPNetworkMessageContentMaskPublisherID
	}
	encoded, err := uadp.Encode(probe, nil)
	if err != nil {
		return failure(exitInternal, "internal", err.Error(), ua.StatusBadEncodingError)
	}
	if _, err := sock.WriteToUDP(encoded, dest); err != nil {
		return failure(exitConnect, "connection", err.Error(), ua.StatusBadCommunicationError)
	}
	collected := f.collect(sock, want)
	writers := f.writers
	if writers == nil {
		writers = []uint16{}
	}
	result := map[string]any{"url": f.url, "type": f.typ, "dataSetWriterIds": writers, "dataSetMetaData": collected.metaData, "writerConfigurations": collected.configurations}
	if len(collected.metaData) == 0 && len(collected.configurations) == 0 {
		res := failure(exitTimeout, "timeout", fmt.Sprintf("no announcement within %d ms", f.timeoutMS), ua.StatusBadTimeout)
		res.results = []any{result}
		return res
	}
	return outcome{status: ua.StatusOK, results: []any{result}}
}

type announcements struct {
	metaData, configurations []any
}

// collect gathers the announcements of the wanted type until the timeout.
func (f *discoverFlags) collect(sock *net.UDPConn, want message.DiscoveryType) announcements {
	got := announcements{metaData: []any{}, configurations: []any{}}
	_ = sock.SetReadDeadline(time.Now().Add(time.Duration(f.timeoutMS) * time.Millisecond))
	seen := map[string]bool{}
	buf := make([]byte, 65536)
	for {
		n, _, err := sock.ReadFromUDP(buf)
		if err != nil {
			return got
		}
		kind, chunk, err := uadp.PeekType(buf[:n])
		if err != nil || chunk || kind != message.NetworkMessageDiscoveryResponse {
			continue
		}
		nm, err := uadp.Decode(buf[:n], nil)
		if err != nil || nm.Discovery == nil || nm.Discovery.Type != want {
			continue
		}
		key, item := describeAnnouncement(nm)
		if seen[key] {
			continue
		}
		seen[key] = true
		if want == message.DiscoveryDataSetMetaData {
			got.metaData = append(got.metaData, item)
		} else {
			got.configurations = append(got.configurations, item)
		}
	}
}

func describeAnnouncement(nm *message.NetworkMessage) (string, map[string]any) {
	d := nm.Discovery
	item := map[string]any{"publisherId": psPublisherIDOf(nm.PublisherID), "writerGroupId": nm.GroupHeader.WriterGroupID}
	if d.Type == message.DiscoveryDataSetMetaData {
		fields := []any{}
		if d.MetaData != nil {
			for _, field := range d.MetaData.Fields {
				fields = append(fields, map[string]any{"name": field.Name, "builtInType": field.BuiltInType, "dataType": field.DataType.String(), "valueRank": field.ValueRank})
			}
		}
		meta := map[string]any{"fields": fields}
		if d.MetaData != nil {
			meta["name"] = d.MetaData.Name
			if v := d.MetaData.ConfigurationVersion; v != nil {
				meta["configurationVersion"] = map[string]any{"majorVersion": v.MajorVersion, "minorVersion": v.MinorVersion}
			}
		}
		item["dataSetWriterId"], item["statusCode"], item["metaData"] = d.DataSetWriterID, statusOf(d.StatusCode), meta
		return fmt.Sprintf("md/%d", d.DataSetWriterID), item
	}
	status := ua.StatusOK
	if len(d.StatusCodes) > 0 {
		status = d.StatusCodes[0]
	}
	item["dataSetWriterIds"], item["statusCode"] = d.DataSetWriterIDs, statusOf(status)
	if g := d.WriterGroup; g != nil {
		writers := []any{}
		for _, w := range g.DataSetWriters {
			writers = append(writers, map[string]any{"name": w.Name, "dataSetWriterId": w.DataSetWriterID, "dataSetName": w.DataSetName})
		}
		item["writerGroupId"] = g.WriterGroupID
		item["writerGroup"] = map[string]any{"name": g.Name, "writerGroupId": g.WriterGroupID, "publishingInterval": g.PublishingInterval, "dataSetWriters": writers}
	}
	return fmt.Sprintf("cfg/%v", d.DataSetWriterIDs), item
}
