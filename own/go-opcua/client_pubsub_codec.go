// SPDX-License-Identifier: MIT

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"unicode"

	"github.com/otfabric/go-opcua/pubsub/jsonmsg"
	"github.com/otfabric/go-opcua/pubsub/message"
	"github.com/otfabric/go-opcua/pubsub/uadp"
	"github.com/otfabric/go-opcua/ua"
)

var pubsubCodecOps = []string{"pubsub-uadp-encode", "pubsub-uadp-decode", "pubsub-json-encode", "pubsub-json-decode"}

// parseMetaData reads --metadata: one DataSetMetaDataType, or a list by DataSetWriterId.
func parseMetaData(doc []byte) (message.MetaDataLookup, error) {
	var list []struct {
		WriterID uint16          `json:"dataSetWriterId"`
		MetaData json.RawMessage `json:"metaData"`
	}
	if err := json.Unmarshal(doc, &list); err == nil {
		byWriter := map[uint16]*ua.DataSetMetaDataType{}
		for _, item := range list {
			md := &ua.DataSetMetaDataType{}
			if err := ua.DecodeJSON(item.MetaData, md); err != nil {
				return nil, err
			}
			byWriter[item.WriterID] = md
		}
		return func(_ message.PublisherID, _, writer uint16) *ua.DataSetMetaDataType { return byWriter[writer] }, nil
	}
	md := &ua.DataSetMetaDataType{}
	if err := ua.DecodeJSON(doc, md); err != nil {
		return nil, err
	}
	return func(message.PublisherID, uint16, uint16) *ua.DataSetMetaDataType { return md }, nil
}

func (f *codecFlags) metaDataLookup() (message.MetaDataLookup, error) {
	if f.metadata != "" && f.metadataFile != "" {
		return nil, errors.New("--metadata and --metadata-file exclude each other")
	}
	doc := []byte(f.metadata)
	if f.metadataFile != "" {
		var err error
		if doc, err = os.ReadFile(f.metadataFile); err != nil {
			return nil, err
		}
	}
	if len(doc) == 0 {
		return nil, nil
	}
	return parseMetaData(doc)
}

// pubsubCodec is one of the operations of §14.9.
func (f *codecFlags) pubsubCodec() (res outcome) {
	defer func() {
		if r := recover(); r != nil {
			msg, ok := r.(descError)
			if !ok {
				panic(r)
			}
			res = inputError(string(msg))
		}
	}()
	md, err := f.metaDataLookup()
	if err != nil {
		return inputError("--metadata: " + err.Error())
	}
	doc, err := f.readDocument()
	if err != nil {
		return inputError(err.Error())
	}
	mapping := "uadp"
	if strings.Contains(f.action, "-json-") {
		mapping = "json"
	}
	head := map[string]any{"action": f.action, "mapping": mapping, "statusCode": statusOf(ua.StatusOK)}
	if strings.HasSuffix(f.action, "-encode") {
		return encodePubSub(doc, mapping, md, head)
	}
	return decodePubSub(doc, mapping, md, head)
}

func codecFailure(head map[string]any, err error, fallback ua.StatusCode) outcome {
	status := fallback
	var known ua.StatusCode
	if errors.As(err, &known) {
		status = known
	}
	head["statusCode"] = statusOf(status)
	res := failure(exitService, "service", err.Error(), status)
	res.results = []any{head}
	return res
}

func encodePubSub(doc []byte, mapping string, md message.MetaDataLookup, head map[string]any) outcome {
	desc := &psDesc{}
	d := json.NewDecoder(strings.NewReader(string(doc)))
	if err := d.Decode(desc); err != nil {
		return inputError("description: " + err.Error())
	}
	nm := desc.model(mapping)
	var out []byte
	var err error
	if mapping == "json" {
		out, err = jsonmsg.Encode(nm, &jsonmsg.EncodeOptions{MetaData: md})
	} else {
		out, err = uadp.Encode(nm, &uadp.EncodeOptions{MetaData: md})
	}
	if err != nil {
		return codecFailure(head, err, ua.StatusBadEncodingError)
	}
	if mapping == "json" {
		head["encoded"] = string(out)
	} else {
		head["encoded"] = base64.StdEncoding.EncodeToString(out)
	}
	head["length"] = len(out)
	return outcome{status: ua.StatusOK, results: []any{head}}
}

func decodePubSub(doc []byte, mapping string, md message.MetaDataLookup, head map[string]any) outcome {
	var nm *message.NetworkMessage
	var err error
	var described psDesc
	var reencoded any
	var reencodeErr error
	if mapping == "json" {
		nm, err = jsonmsg.Decode(doc, &jsonmsg.DecodeOptions{MetaData: md})
		if err != nil {
			return codecFailure(head, err, ua.StatusBadDecodingError)
		}
		described = describeJSON(nm)
		out, encErr := jsonmsg.Encode(nm, &jsonmsg.EncodeOptions{MetaData: md})
		reencoded, reencodeErr = string(out), encErr
	} else {
		raw, b64Err := base64.StdEncoding.DecodeString(strings.Map(dropSpace, string(doc)))
		if b64Err != nil {
			return inputError("not Base64: " + b64Err.Error())
		}
		nm, err = uadp.Decode(raw, &uadp.DecodeOptions{MetaData: md})
		if err != nil {
			return codecFailure(head, err, ua.StatusBadDecodingError)
		}
		described = describeUADP(nm, md)
		out, encErr := uadp.Encode(nm, &uadp.EncodeOptions{MetaData: md})
		reencoded, reencodeErr = base64.StdEncoding.EncodeToString(out), encErr
	}
	head["networkMessage"] = described
	head["reencodeStatusCode"] = statusOf(ua.StatusOK)
	if reencodeErr != nil {
		status := ua.StatusBadEncodingError
		var known ua.StatusCode
		if errors.As(reencodeErr, &known) {
			status = known
		}
		head["reencodeStatusCode"] = statusOf(status)
	} else {
		head["reencoded"] = reencoded
	}
	return outcome{status: ua.StatusOK, results: []any{head}}
}

func dropSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}
