package ingest

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"testing"
)

func TestMinidumpEndpointStoresEventDumpAndAttachments(t *testing.T) {
	st, _ := testProject(t)
	service := New(st, 20<<20)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	dumpHeader := make(textproto.MIMEHeader)
	dumpHeader.Set("Content-Disposition", `form-data; name="upload_file_minidump"; filename="crash.dmp"`)
	dumpHeader.Set("Content-Type", "application/octet-stream")
	dumpPart, _ := writer.CreatePart(dumpHeader)
	_, _ = dumpPart.Write(minimalMinidump())
	metadata, _ := writer.CreateFormField("sentry")
	_, _ = metadata.Write([]byte(`{"event_id":"dddddddddddddddddddddddddddddddd","release":"desktop@1.0","environment":"production"}`))
	logHeader := make(textproto.MIMEHeader)
	logHeader.Set("Content-Disposition", `form-data; name="upload_file_log"; filename="crash.log"`)
	logHeader.Set("Content-Type", "text/plain")
	logPart, _ := writer.CreatePart(logHeader)
	_, _ = logPart.Write([]byte("fatal native crash"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/1/minidump/?sentry_key=public-key", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()
	service.Minidump(response, request, "1")
	if response.Code != http.StatusOK {
		t.Fatalf("minidump status=%d body=%s", response.Code, response.Body.String())
	}
	var result Result
	if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.ID != "dddddddddddddddddddddddddddddddd" {
		t.Fatalf("minidump response = %s", response.Body.String())
	}
	var events, attachments, releases int
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM events WHERE event_id = ? AND platform = 'native'`, result.ID).Scan(&events)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM event_attachments ea JOIN events e ON e.id = ea.event_id WHERE e.event_id = ?`, result.ID).Scan(&attachments)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM releases WHERE version = 'desktop@1.0'`).Scan(&releases)
	if events != 1 || attachments != 2 || releases != 1 {
		t.Fatalf("minidump events=%d attachments=%d releases=%d", events, attachments, releases)
	}
}

func TestMinidumpEndpointRejectsInvalidDump(t *testing.T) {
	st, _ := testProject(t)
	service := New(st, 20<<20)
	request := httptest.NewRequest(http.MethodPost, "/api/1/minidump/?sentry_key=public-key", bytes.NewBufferString("not a dump"))
	request.Header.Set("Content-Type", "application/octet-stream")
	response := httptest.NewRecorder()
	service.Minidump(response, request, "1")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid minidump status=%d body=%s", response.Code, response.Body.String())
	}
}

func minimalMinidump() []byte {
	const (
		systemRVA    = 72
		exceptionRVA = 80
		threadRVA    = 248
		contextRVA   = 304
		stackRVA     = 560
		stackAddress = 0x70000000
		imageAddress = 0x140001010
	)
	dump := make([]byte, 624)
	copy(dump[:4], "MDMP")
	binary.LittleEndian.PutUint32(dump[8:12], 3)
	binary.LittleEndian.PutUint32(dump[12:16], 32)
	for index, stream := range []struct {
		kind, size, rva uint32
	}{{7, 2, systemRVA}, {6, 168, exceptionRVA}, {3, 52, threadRVA}} {
		offset := 32 + index*12
		binary.LittleEndian.PutUint32(dump[offset:offset+4], stream.kind)
		binary.LittleEndian.PutUint32(dump[offset+4:offset+8], stream.size)
		binary.LittleEndian.PutUint32(dump[offset+8:offset+12], stream.rva)
	}
	binary.LittleEndian.PutUint16(dump[systemRVA:systemRVA+2], 9)
	binary.LittleEndian.PutUint32(dump[exceptionRVA:exceptionRVA+4], 7)
	binary.LittleEndian.PutUint32(dump[exceptionRVA+8:exceptionRVA+12], 0xc0000005)
	binary.LittleEndian.PutUint64(dump[exceptionRVA+24:exceptionRVA+32], imageAddress)
	binary.LittleEndian.PutUint32(dump[exceptionRVA+160:exceptionRVA+164], 256)
	binary.LittleEndian.PutUint32(dump[exceptionRVA+164:exceptionRVA+168], contextRVA)
	binary.LittleEndian.PutUint32(dump[threadRVA:threadRVA+4], 1)
	binary.LittleEndian.PutUint32(dump[threadRVA+4:threadRVA+8], 7)
	binary.LittleEndian.PutUint64(dump[threadRVA+28:threadRVA+36], stackAddress)
	binary.LittleEndian.PutUint32(dump[threadRVA+36:threadRVA+40], 64)
	binary.LittleEndian.PutUint32(dump[threadRVA+40:threadRVA+44], stackRVA)
	binary.LittleEndian.PutUint32(dump[threadRVA+44:threadRVA+48], 256)
	binary.LittleEndian.PutUint32(dump[threadRVA+48:threadRVA+52], contextRVA)
	binary.LittleEndian.PutUint64(dump[contextRVA+152:contextRVA+160], stackAddress)
	binary.LittleEndian.PutUint64(dump[contextRVA+248:contextRVA+256], imageAddress)
	return dump
}
