package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// The connection test offers the model no tool. With the SDK's default tool list
// it would hand a model that answers with a tool call a shell and file access in
// bypass mode, outside every agent hook, gate and confinement.
func TestConnectionOffersNoTools(t *testing.T) {
	sse := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_1","usage":{"input_tokens":3,"output_tokens":1}}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"OK"}}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.Header().Set("content-type", "text/event-stream")
		_, _ = io.WriteString(w, sse)
	}))
	defer srv.Close()

	_, reply, err := TestConnection(context.Background(), Config{Format: llm.FormatAnthropic, BaseURL: srv.URL, APIKey: "k", Model: "m", Stream: true})
	if err != nil || reply != "OK" {
		t.Fatalf("connection test: reply %q, err %v", reply, err)
	}
	if len(bodies) != 1 {
		t.Fatalf("%d requests, want 1", len(bodies))
	}
	var req struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &req); err != nil {
		t.Fatalf("request body %q: %v", bodies[0], err)
	}
	if len(req.Tools) != 0 {
		names := make([]string, 0, len(req.Tools))
		for _, tl := range req.Tools {
			names = append(names, tl.Name)
		}
		t.Fatalf("connection test offered tools %v", names)
	}
}
