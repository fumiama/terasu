package http2

import (
	"io"
	"testing"
)

func TestClientGet(t *testing.T) {
	resp, err := Get("https://huggingface.co/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	t.Log("[T] response code", resp.StatusCode)
	for k, vs := range resp.Header {
		for _, v := range vs {
			t.Log("[T] response header", k+":", v)
		}
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fail()
	}
	t.Log(string(data))
}
