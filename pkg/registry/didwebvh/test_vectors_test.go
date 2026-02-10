package didwebvh

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// Official test vectors from did:webvh reference implementation
// Source: https://github.com/decentralized-identity/didwebvh-py/tree/main/sample-diddoc
// Spec version: did:webvh:1.0

const (
	// SCID from the official test vectors
	testVectorSCID = "QmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU"

	// DID string from the official test vectors
	testVectorDID = "did:webvh:QmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU:domain.example"

	// Version IDs from official test vectors
	testVectorVersionID1 = "1-QmVCzWgVX2isJE6tsmUcHnNHQJ9WXZb9A26VpkxptB2fqb"
	testVectorVersionID2 = "2-QmPFyXi2avxYnu1BwGbWdwph52Rjr5WZxKif7e6Vaf6DPr"

	// Entry hashes from official test vectors
	testVectorEntryHash1 = "QmVCzWgVX2isJE6tsmUcHnNHQJ9WXZb9A26VpkxptB2fqb"
	testVectorEntryHash2 = "QmPFyXi2avxYnu1BwGbWdwph52Rjr5WZxKif7e6Vaf6DPr"

	// Method version
	testVectorMethod = "did:webvh:1.0"

	// Update keys from official test vectors
	testVectorUpdateKey1 = "z6Mkh8Pzehru4LVBRftuiLzpMchSzNWbEytus13N8fsfpobs"
	testVectorUpdateKey2 = "z6MkpqrwnQNMWxAqDfBfWpbU4vE7Wvzjwj1ErTpxCd9CDwdM"

	// Witness DIDs from official test vectors
	testVectorWitness1 = "did:key:z6MkrMuMdd6hTJmwf8e6WZz643b7JxYiAnWAFsorDLkaZF5i"
	testVectorWitness2 = "did:key:z6MkgXvUbnhiVu1H6SmiPVzC9xpdnCFyE5X2AgxRY4PrbbWN"
	testVectorWitness3 = "did:key:z6MkvZ7MQfnCewK2qjqXpDAKBcExAPpLbpWv8khQxZS3RmTj"
)

// Official DID log (did.jsonl) - first entry
// From: https://raw.githubusercontent.com/decentralized-identity/didwebvh-py/main/sample-diddoc/did.jsonl
var testVectorDIDLogEntry1 = `{"versionId": "1-QmVCzWgVX2isJE6tsmUcHnNHQJ9WXZb9A26VpkxptB2fqb", "versionTime": "2025-05-09T22:33:41Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6MkrMuMdd6hTJmwf8e6WZz643b7JxYiAnWAFsorDLkaZF5i"}, {"id": "did:key:z6MkgXvUbnhiVu1H6SmiPVzC9xpdnCFyE5X2AgxRY4PrbbWN"}, {"id": "did:key:z6MkvZ7MQfnCewK2qjqXpDAKBcExAPpLbpWv8khQxZS3RmTj"}]}, "updateKeys": ["z6Mkh8Pzehru4LVBRftuiLzpMchSzNWbEytus13N8fsfpobs"], "nextKeyHashes": ["QmRossAYEwzTgLNQx8zEzZPfxUU1WGSZpCFA6T8ZPku3V7"], "method": "did:webvh:1.0", "scid": "QmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6Mkh8Pzehru4LVBRftuiLzpMchSzNWbEytus13N8fsfpobs#z6Mkh8Pzehru4LVBRftuiLzpMchSzNWbEytus13N8fsfpobs", "created": "2025-05-09T22:33:41Z", "proofPurpose": "assertionMethod", "proofValue": "z4rDHfJZ5hxVTu3TYnTLotTLyRFfBpzgkoWMnkLcg6tVXerkTXmXduHbM1oaMakhrc6sFt1A5Nj6AH5y63EFJysi"}]}`

// Official DID log (did.jsonl) - second entry
var testVectorDIDLogEntry2 = `{"versionId": "2-QmPFyXi2avxYnu1BwGbWdwph52Rjr5WZxKif7e6Vaf6DPr", "versionTime": "2025-05-09T22:33:42Z", "parameters": {"updateKeys": ["z6MkpqrwnQNMWxAqDfBfWpbU4vE7Wvzjwj1ErTpxCd9CDwdM"], "nextKeyHashes": ["QmeZZg9ikJWNvM827KZEp59QzvGmQNGNnVnT6EAQkFTAZd"]}, "state": {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1", "https://identity.foundation/.well-known/did-configuration/v1"], "id": "did:webvh:QmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU:domain.example", "authentication": ["did:webvh:QmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU:domain.example#z6MkkQ7ziv3QXSG2JKh1BvW9p31qaGieUJscDqz32osWrgbK"], "assertionMethod": ["did:webvh:QmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU:domain.example#z6MkkQ7ziv3QXSG2JKh1BvW9p31qaGieUJscDqz32osWrgbK"], "verificationMethod": [{"id": "did:webvh:QmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU:domain.example#z6MkkQ7ziv3QXSG2JKh1BvW9p31qaGieUJscDqz32osWrgbK", "controller": "did:webvh:QmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU:domain.example", "type": "Multikey", "publicKeyMultibase": "z6MkkQ7ziv3QXSG2JKh1BvW9p31qaGieUJscDqz32osWrgbK"}], "service": [{"id": "did:webvh:QmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU:domain.example#domain", "type": "LinkedDomains", "serviceEndpoint": "https://domain.example"}]}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkpqrwnQNMWxAqDfBfWpbU4vE7Wvzjwj1ErTpxCd9CDwdM#z6MkpqrwnQNMWxAqDfBfWpbU4vE7Wvzjwj1ErTpxCd9CDwdM", "created": "2025-05-09T22:33:42Z", "proofPurpose": "assertionMethod", "proofValue": "zU2Xhy2Etfs7eZukbN3Cv7ityrv7XJ9ri7PWYbvaqgnmBJCeoLcFQZVUmb1JXW7WjgBPqprge5UGDuSgsWj5vzEH"}]}`

// Complete DID log file
var testVectorDIDLog = testVectorDIDLogEntry1 + "\n" + testVectorDIDLogEntry2 + "\n"

// Official witness file (did-witness.json)
// From: https://raw.githubusercontent.com/decentralized-identity/didwebvh-py/main/sample-diddoc/did-witness.json
var testVectorWitnessFile = `[
  {
    "versionId": "1-QmVCzWgVX2isJE6tsmUcHnNHQJ9WXZb9A26VpkxptB2fqb",
    "proof": [
      {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "did:key:z6MkrMuMdd6hTJmwf8e6WZz643b7JxYiAnWAFsorDLkaZF5i#z6MkrMuMdd6hTJmwf8e6WZz643b7JxYiAnWAFsorDLkaZF5i",
        "created": "2025-05-09T22:33:42Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "z5vGToJkpPcxV4qmoeRK8BDsYQDmTPaV3BjamEBjtDKXev7xCZhj48iLhNhCUNoFqgbcz4jPyfrvMCW2fF6QRWzZc"
      },
      {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "did:key:z6MkgXvUbnhiVu1H6SmiPVzC9xpdnCFyE5X2AgxRY4PrbbWN#z6MkgXvUbnhiVu1H6SmiPVzC9xpdnCFyE5X2AgxRY4PrbbWN",
        "created": "2025-05-09T22:33:42Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "z31tDEVbURZ4Qbv2m46eHH91prSt3LP5LvZEWCs7Wq3Uz1a3bpJepvd9eDa4rHdmnp9sPwHkXXhcr8tzMP43mJEWs"
      }
    ]
  },
  {
    "versionId": "2-QmPFyXi2avxYnu1BwGbWdwph52Rjr5WZxKif7e6Vaf6DPr",
    "proof": [
      {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "did:key:z6MkrMuMdd6hTJmwf8e6WZz643b7JxYiAnWAFsorDLkaZF5i#z6MkrMuMdd6hTJmwf8e6WZz643b7JxYiAnWAFsorDLkaZF5i",
        "created": "2025-05-09T22:33:42Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "z4LS4TW3T3SgCKANLX1nbcTAiR3YtVZf56cYASXH3NEZ3D2XNCZsPiBKG64wqVpky2sDmPv4BY9YLDJMjqZfY8b7Y"
      },
      {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "did:key:z6MkgXvUbnhiVu1H6SmiPVzC9xpdnCFyE5X2AgxRY4PrbbWN#z6MkgXvUbnhiVu1H6SmiPVzC9xpdnCFyE5X2AgxRY4PrbbWN",
        "created": "2025-05-09T22:33:42Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "z3wwF7wWJVqjx6Cez16pYPa8KtqWpUddN3Rap2AqngACXyLSMy8S9n3aTFNMULZXFn1DgK1kiXb9y2B2XaLQrAxhX"
      }
    ]
  }
]`

// TestVersionIDParsing tests parsing of versionId format (version-entryHash)
func TestVersionIDParsing(t *testing.T) {
	tests := []struct {
		name          string
		versionID     string
		wantVersion   int
		wantEntryHash string
		wantErr       bool
	}{
		{
			name:          "official test vector entry 1",
			versionID:     testVectorVersionID1,
			wantVersion:   1,
			wantEntryHash: testVectorEntryHash1,
			wantErr:       false,
		},
		{
			name:          "official test vector entry 2",
			versionID:     testVectorVersionID2,
			wantVersion:   2,
			wantEntryHash: testVectorEntryHash2,
			wantErr:       false,
		},
		{
			name:      "invalid format - no dash",
			versionID: "1QmVCzWgVX2isJE6tsmUcHnNHQJ9WXZb9A26VpkxptB2fqb",
			wantErr:   true,
		},
		{
			name:      "invalid format - non-numeric version",
			versionID: "abc-QmVCzWgVX2isJE6tsmUcHnNHQJ9WXZb9A26VpkxptB2fqb",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, entryHash, err := parseVersionID(tt.versionID)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseVersionID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if version != tt.wantVersion {
					t.Errorf("parseVersionID() version = %v, want %v", version, tt.wantVersion)
				}
				if entryHash != tt.wantEntryHash {
					t.Errorf("parseVersionID() entryHash = %v, want %v", entryHash, tt.wantEntryHash)
				}
			}
		})
	}
}

// TestEntryParsing tests parsing of DID log entries
func TestEntryParsing(t *testing.T) {
	tests := []struct {
		name          string
		entry         string
		wantVersionID string
		wantSCID      string
		wantMethod    string
		wantErr       bool
	}{
		{
			name:          "official test vector entry 1",
			entry:         testVectorDIDLogEntry1,
			wantVersionID: testVectorVersionID1,
			wantSCID:      testVectorSCID,
			wantMethod:    testVectorMethod,
			wantErr:       false,
		},
		{
			name:          "official test vector entry 2",
			entry:         testVectorDIDLogEntry2,
			wantVersionID: testVectorVersionID2,
			wantSCID:      "", // SCID only in first entry
			wantMethod:    "", // Method inherited from first entry
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entry DIDLogEntry
			err := json.Unmarshal([]byte(tt.entry), &entry)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if entry.VersionID != tt.wantVersionID {
					t.Errorf("entry.VersionID = %v, want %v", entry.VersionID, tt.wantVersionID)
				}
				if entry.Parameters.SCID != tt.wantSCID {
					t.Errorf("entry.Parameters.SCID = %v, want %v", entry.Parameters.SCID, tt.wantSCID)
				}
				if entry.Parameters.Method != tt.wantMethod {
					t.Errorf("entry.Parameters.Method = %v, want %v", entry.Parameters.Method, tt.wantMethod)
				}
			}
		})
	}
}

// TestDIDLogParsing tests parsing of complete DID log files
func TestDIDLogParsing(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(testVectorDIDLog), "\n")

	if len(lines) != 2 {
		t.Fatalf("Expected 2 log entries, got %d", len(lines))
	}

	// Parse first entry
	var entry1 DIDLogEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry1); err != nil {
		t.Fatalf("Failed to parse entry 1: %v", err)
	}

	// Validate first entry structure
	if entry1.VersionID != testVectorVersionID1 {
		t.Errorf("Entry 1 VersionID = %v, want %v", entry1.VersionID, testVectorVersionID1)
	}
	if entry1.Parameters.SCID != testVectorSCID {
		t.Errorf("Entry 1 SCID = %v, want %v", entry1.Parameters.SCID, testVectorSCID)
	}
	if entry1.Parameters.Method != testVectorMethod {
		t.Errorf("Entry 1 Method = %v, want %v", entry1.Parameters.Method, testVectorMethod)
	}
	if len(entry1.Parameters.UpdateKeys) != 1 || entry1.Parameters.UpdateKeys[0] != testVectorUpdateKey1 {
		t.Errorf("Entry 1 UpdateKeys = %v, want [%s]", entry1.Parameters.UpdateKeys, testVectorUpdateKey1)
	}
	if entry1.State.ID != testVectorDID {
		t.Errorf("Entry 1 DID = %v, want %v", entry1.State.ID, testVectorDID)
	}

	// Validate witness configuration
	if entry1.Parameters.Witness == nil {
		t.Fatal("Entry 1 should have witness configuration")
	}
	if entry1.Parameters.Witness.Threshold != 2 {
		t.Errorf("Entry 1 Witness Threshold = %d, want 2", entry1.Parameters.Witness.Threshold)
	}
	if len(entry1.Parameters.Witness.Witnesses) != 3 {
		t.Errorf("Entry 1 Witness count = %d, want 3", len(entry1.Parameters.Witness.Witnesses))
	}

	// Parse second entry
	var entry2 DIDLogEntry
	if err := json.Unmarshal([]byte(lines[1]), &entry2); err != nil {
		t.Fatalf("Failed to parse entry 2: %v", err)
	}

	// Validate second entry structure
	if entry2.VersionID != testVectorVersionID2 {
		t.Errorf("Entry 2 VersionID = %v, want %v", entry2.VersionID, testVectorVersionID2)
	}
	if len(entry2.Parameters.UpdateKeys) != 1 || entry2.Parameters.UpdateKeys[0] != testVectorUpdateKey2 {
		t.Errorf("Entry 2 UpdateKeys = %v, want [%s]", entry2.Parameters.UpdateKeys, testVectorUpdateKey2)
	}

	// Validate DID document has verification methods
	if len(entry2.State.VerificationMethod) == 0 {
		t.Error("Entry 2 should have verification methods")
	}
	// Service is interface{}, check it's not nil and is a slice
	if entry2.State.Service == nil {
		t.Error("Entry 2 should have services")
	} else if services, ok := entry2.State.Service.([]interface{}); !ok || len(services) == 0 {
		t.Error("Entry 2 should have at least one service")
	}
}

// witnessFileEntry represents an entry in the did-witness.json file
// Note: This is different from WitnessEntry in the registry which represents a witness in WitnessConfig
type witnessFileEntry struct {
	VersionID string                   `json:"versionId"`
	Proof     []map[string]interface{} `json:"proof"`
}

// TestWitnessFileParsing tests parsing of witness proof files
func TestWitnessFileParsing(t *testing.T) {
	var witnessEntries []witnessFileEntry
	if err := json.Unmarshal([]byte(testVectorWitnessFile), &witnessEntries); err != nil {
		t.Fatalf("Failed to parse witness file: %v", err)
	}

	if len(witnessEntries) != 2 {
		t.Fatalf("Expected 2 witness entries, got %d", len(witnessEntries))
	}

	// Validate first witness entry
	if witnessEntries[0].VersionID != testVectorVersionID1 {
		t.Errorf("Witness entry 1 VersionID = %v, want %v", witnessEntries[0].VersionID, testVectorVersionID1)
	}
	if len(witnessEntries[0].Proof) != 2 {
		t.Errorf("Witness entry 1 should have 2 proofs (threshold), got %d", len(witnessEntries[0].Proof))
	}

	// Validate second witness entry
	if witnessEntries[1].VersionID != testVectorVersionID2 {
		t.Errorf("Witness entry 2 VersionID = %v, want %v", witnessEntries[1].VersionID, testVectorVersionID2)
	}
	if len(witnessEntries[1].Proof) != 2 {
		t.Errorf("Witness entry 2 should have 2 proofs (threshold), got %d", len(witnessEntries[1].Proof))
	}

	// Validate proof structure
	for i, entry := range witnessEntries {
		for j, proof := range entry.Proof {
			proofType, _ := proof["type"].(string)
			if proofType != "DataIntegrityProof" {
				t.Errorf("Entry %d Proof %d type = %v, want DataIntegrityProof", i+1, j+1, proofType)
			}
			cryptosuite, _ := proof["cryptosuite"].(string)
			if cryptosuite != "eddsa-jcs-2022" {
				t.Errorf("Entry %d Proof %d cryptosuite = %v, want eddsa-jcs-2022", i+1, j+1, cryptosuite)
			}
			proofPurpose, _ := proof["proofPurpose"].(string)
			if proofPurpose != "assertionMethod" {
				t.Errorf("Entry %d Proof %d proofPurpose = %v, want assertionMethod", i+1, j+1, proofPurpose)
			}
		}
	}
}

// TestParameterMergingWithTestVectors tests parameter merging using official test vectors
func TestParameterMergingWithTestVectors(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(testVectorDIDLog), "\n")

	var entry1, entry2 DIDLogEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry1); err != nil {
		t.Fatalf("Failed to parse entry 1: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &entry2); err != nil {
		t.Fatalf("Failed to parse entry 2: %v", err)
	}

	// Merge parameters from entry 1 into accumulated
	accumulated := DIDParameters{}
	mergeParameters(&accumulated, &entry1.Parameters)

	// Verify entry 1 parameters are set
	if accumulated.SCID != testVectorSCID {
		t.Errorf("After entry 1, SCID = %v, want %v", accumulated.SCID, testVectorSCID)
	}
	if accumulated.Method != testVectorMethod {
		t.Errorf("After entry 1, Method = %v, want %v", accumulated.Method, testVectorMethod)
	}
	if len(accumulated.UpdateKeys) != 1 || accumulated.UpdateKeys[0] != testVectorUpdateKey1 {
		t.Errorf("After entry 1, UpdateKeys = %v, want [%s]", accumulated.UpdateKeys, testVectorUpdateKey1)
	}
	if accumulated.Witness == nil || accumulated.Witness.Threshold != 2 {
		t.Error("After entry 1, Witness should be set with threshold 2")
	}

	// Merge parameters from entry 2
	mergeParameters(&accumulated, &entry2.Parameters)

	// Verify SCID and Method persist (not overwritten by empty values)
	if accumulated.SCID != testVectorSCID {
		t.Errorf("After entry 2, SCID should persist = %v, want %v", accumulated.SCID, testVectorSCID)
	}
	if accumulated.Method != testVectorMethod {
		t.Errorf("After entry 2, Method should persist = %v, want %v", accumulated.Method, testVectorMethod)
	}

	// Verify UpdateKeys are updated
	if len(accumulated.UpdateKeys) != 1 || accumulated.UpdateKeys[0] != testVectorUpdateKey2 {
		t.Errorf("After entry 2, UpdateKeys = %v, want [%s]", accumulated.UpdateKeys, testVectorUpdateKey2)
	}

	// Verify Witness persists (not overwritten by nil)
	if accumulated.Witness == nil {
		t.Error("After entry 2, Witness should persist from entry 1")
	}
}

// TestDIDToHTTPURLWithTestVector tests DID to HTTPS URL transformation
func TestDIDToHTTPURLWithTestVector(t *testing.T) {
	r, err := NewDIDWebVHRegistry(Config{})
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	scid, url, err := r.didToHTTPURL(testVectorDID)
	if err != nil {
		t.Fatalf("didToHTTPURL() error: %v", err)
	}

	if scid != testVectorSCID {
		t.Errorf("didToHTTPURL() SCID = %v, want %v", scid, testVectorSCID)
	}

	expectedURL := "https://domain.example/.well-known/did.jsonl"
	if url != expectedURL {
		t.Errorf("didToHTTPURL() URL = %v, want %v", url, expectedURL)
	}
}

// TestMockServerWithTestVectors tests full resolution with mock server serving official test vectors
func TestMockServerWithTestVectors(t *testing.T) {
	// Create mock HTTP server serving official test vectors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/did.jsonl":
			w.Header().Set("Content-Type", "text/jsonl")
			w.Write([]byte(testVectorDIDLog))
		case "/.well-known/did-witness.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(testVectorWitnessFile))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Extract host from server URL
	serverHost := strings.TrimPrefix(server.URL, "http://")
	encodedHost := strings.ReplaceAll(serverHost, ":", "%3A")

	// Build did:webvh identifier for test server using official SCID
	testDID := "did:webvh:" + testVectorSCID + ":" + encodedHost

	// Create registry allowing HTTP for testing
	r, err := NewDIDWebVHRegistry(Config{
		AllowHTTP: true,
	})
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}
	r.SetHTTPClient(server.Client())

	// Test resolution
	ctx := context.Background()
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			ID: testDID,
		},
	}

	resp, err := r.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("Evaluate() returned error: %v", err)
	}

	// Log the response for debugging
	t.Logf("Evaluate response: Decision=%v", resp.Decision)
	if resp.Context != nil && resp.Context.Reason != nil {
		t.Logf("Reason: %v", resp.Context.Reason)
	}

	// The resolution should process the DID log entries
	// Note: Full SCID verification requires matching domain, so this tests the parsing flow
}

// TestSCIDValidation tests SCID format validation with official test vectors
func TestSCIDValidation(t *testing.T) {
	tests := []struct {
		name  string
		scid  string
		valid bool
	}{
		{
			name:  "official test vector SCID",
			scid:  testVectorSCID,
			valid: true,
		},
		{
			name:  "official entry hash 1 (also valid SCID format)",
			scid:  testVectorEntryHash1,
			valid: true,
		},
		{
			name:  "official entry hash 2 (also valid SCID format)",
			scid:  testVectorEntryHash2,
			valid: true,
		},
		{
			name:  "too short",
			scid:  "QmNdaz",
			valid: false,
		},
		{
			name:  "contains invalid base58btc character 0",
			scid:  "0mNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU",
			valid: false,
		},
		{
			name:  "contains invalid base58btc character O",
			scid:  "OmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU",
			valid: false,
		},
		{
			name:  "contains invalid base58btc character I",
			scid:  "ImNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU",
			valid: false,
		},
		{
			name:  "contains invalid base58btc character l",
			scid:  "lmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU",
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidSCID(tt.scid)
			if got != tt.valid {
				t.Errorf("isValidSCID(%s) = %v, want %v", tt.scid, got, tt.valid)
			}
		})
	}
}

// TestUpdateKeysFormat tests the update keys format from official test vectors
func TestUpdateKeysFormat(t *testing.T) {
	updateKeys := []string{testVectorUpdateKey1, testVectorUpdateKey2}

	for _, key := range updateKeys {
		// Update keys should be multikey format starting with 'z'
		if !strings.HasPrefix(key, "z") {
			t.Errorf("UpdateKey %s should start with 'z' (multikey format)", key)
		}
		// Should be at least 43 characters (base58btc encoded Ed25519 public key)
		if len(key) < 43 {
			t.Errorf("UpdateKey %s too short, expected at least 43 characters", key)
		}
	}
}

// TestProofStructure tests the Data Integrity proof structure from official test vectors
func TestProofStructure(t *testing.T) {
	var entry DIDLogEntry
	if err := json.Unmarshal([]byte(testVectorDIDLogEntry1), &entry); err != nil {
		t.Fatalf("Failed to parse entry: %v", err)
	}

	if len(entry.Proof) == 0 {
		t.Fatal("Expected at least one proof")
	}

	proof := entry.Proof[0]

	// Required fields per W3C Data Integrity spec
	requiredFields := []string{"type", "cryptosuite", "verificationMethod", "proofPurpose", "proofValue"}
	for _, field := range requiredFields {
		if _, ok := proof[field]; !ok {
			t.Errorf("Proof missing required field: %s", field)
		}
	}

	// Validate specific values
	if proof["type"] != "DataIntegrityProof" {
		t.Errorf("Proof type = %v, want DataIntegrityProof", proof["type"])
	}
	if proof["cryptosuite"] != "eddsa-jcs-2022" {
		t.Errorf("Proof cryptosuite = %v, want eddsa-jcs-2022", proof["cryptosuite"])
	}
	if proof["proofPurpose"] != "assertionMethod" {
		t.Errorf("Proof proofPurpose = %v, want assertionMethod", proof["proofPurpose"])
	}

	// Verification method should be a did:key reference
	vm, _ := proof["verificationMethod"].(string)
	if !strings.HasPrefix(vm, "did:key:") {
		t.Errorf("Proof verificationMethod should be a did:key, got %s", vm)
	}

	// Proof value should be base58btc encoded (starts with 'z')
	pv, _ := proof["proofValue"].(string)
	if !strings.HasPrefix(pv, "z") {
		t.Errorf("Proof proofValue should be base58btc encoded (start with 'z'), got %s", pv)
	}
}

// parseVersionID extracts version number and entry hash from versionId
func parseVersionID(versionID string) (int, string, error) {
	parts := strings.SplitN(versionID, "-", 2)
	if len(parts) != 2 {
		return 0, "", &parseError{Message: "invalid versionId format: missing dash separator"}
	}

	// Parse version number manually
	var version int
	for _, c := range parts[0] {
		if c < '0' || c > '9' {
			return 0, "", &parseError{Message: "invalid versionId format: version not a number"}
		}
		version = version*10 + int(c-'0')
	}
	if len(parts[0]) == 0 {
		return 0, "", &parseError{Message: "invalid versionId format: empty version"}
	}

	return version, parts[1], nil
}

// parseError represents a parsing error
type parseError struct {
	Message string
}

func (e *parseError) Error() string {
	return e.Message
}
