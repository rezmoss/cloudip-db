// Package main builds the cloudip.msgpack file from cloud-provider-ip-addresses JSON data.
package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	baseURL = "https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main"
)

// Provider configuration
var providers = []struct {
	Name     string
	JSONPath string
}{
	{"aws", "aws/aws_ips.json"},
	{"gcp", "googlecloud/googlecloud_ips.json"},
	{"cloudflare", "cloudflare/cloudflare_ips.json"},
	{"azure", "azure/azure_ips.json"},
	{"digitalocean", "digitalocean/digitalocean_ips.json"},
	{"oracle", "oracle/oracle_ips.json"},
}

// SourceEntry represents an entry from the source JSON
type SourceEntry struct {
	IPAddress string `json:"ip_address"`
	IPType    string `json:"ip_type"`
	Service   string `json:"service,omitempty"`
	Region    string `json:"region,omitempty"`
}

// Range represents an IP range in the output format
type Range struct {
	CIDR     string `msgpack:"cidr" json:"cidr"`
	Provider int    `msgpack:"p" json:"p"`
	Region   string `msgpack:"r,omitempty" json:"r,omitempty"`
	Service  string `msgpack:"s,omitempty" json:"s,omitempty"`
}

// Database represents the complete MessagePack database
type Database struct {
	Version   string   `msgpack:"version" json:"version"`
	BuildTime int64    `msgpack:"build_time" json:"build_time"`
	Providers []string `msgpack:"providers" json:"providers"`
	Ranges    []Range  `msgpack:"ranges" json:"ranges"`
}

// VersionInfo for version.json
type VersionInfo struct {
	Version   string `json:"version"`
	BuildTime int64  `json:"build_time"`
	SHA256    string `json:"sha256"`
	Ranges    int    `json:"ranges"`
	Size      int64  `json:"size"`
	SizeGzip  int64  `json:"size_gzip"`
}

func main() {
	fmt.Println("CloudIP Database Builder")
	fmt.Println("========================")

	// Determine output directory
	outputDir := "data"
	if len(os.Args) > 1 {
		outputDir = os.Args[1]
	}

	// Create output directory if needed
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Build provider name list
	providerNames := make([]string, len(providers))
	for i, p := range providers {
		providerNames[i] = p.Name
	}

	// Fetch and process all providers
	var allRanges []Range
	for i, provider := range providers {
		fmt.Printf("\nFetching %s...\n", provider.Name)

		entries, err := fetchProvider(provider.JSONPath)
		if err != nil {
			fmt.Printf("  Warning: %v (skipping)\n", err)
			continue
		}

		// Convert entries to ranges
		for _, entry := range entries {
			r := Range{
				CIDR:     entry.IPAddress,
				Provider: i,
			}
			if entry.Region != "" {
				r.Region = entry.Region
			}
			if entry.Service != "" {
				r.Service = normalizeService(entry.Service)
			}
			allRanges = append(allRanges, r)
		}

		fmt.Printf("  Loaded %d ranges\n", len(entries))
	}

	if len(allRanges) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No ranges loaded from any provider\n")
		os.Exit(1)
	}

	// Sort ranges for consistent output
	sort.Slice(allRanges, func(i, j int) bool {
		if allRanges[i].Provider != allRanges[j].Provider {
			return allRanges[i].Provider < allRanges[j].Provider
		}
		return allRanges[i].CIDR < allRanges[j].CIDR
	})

	// Build database
	now := time.Now().UTC()
	db := Database{
		Version:   now.Format("2006-01-02"),
		BuildTime: now.Unix(),
		Providers: providerNames,
		Ranges:    allRanges,
	}

	fmt.Printf("\nTotal ranges: %d\n", len(allRanges))

	// Serialize to MessagePack
	msgpackData, err := msgpack.Marshal(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing to MessagePack: %v\n", err)
		os.Exit(1)
	}

	// Calculate SHA256
	hash := sha256.Sum256(msgpackData)
	sha256Hex := hex.EncodeToString(hash[:])

	// Write uncompressed MessagePack
	msgpackPath := filepath.Join(outputDir, "cloudip.msgpack")
	if err := os.WriteFile(msgpackPath, msgpackData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing MessagePack file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Wrote %s (%d bytes)\n", msgpackPath, len(msgpackData))

	// Write gzip compressed version
	gzipPath := filepath.Join(outputDir, "cloudip.msgpack.gz")
	gzipFile, err := os.Create(gzipPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating gzip file: %v\n", err)
		os.Exit(1)
	}

	gzipWriter, err := gzip.NewWriterLevel(gzipFile, gzip.BestCompression)
	if err != nil {
		gzipFile.Close()
		fmt.Fprintf(os.Stderr, "Error creating gzip writer: %v\n", err)
		os.Exit(1)
	}

	if _, err := gzipWriter.Write(msgpackData); err != nil {
		gzipWriter.Close()
		gzipFile.Close()
		fmt.Fprintf(os.Stderr, "Error writing gzip data: %v\n", err)
		os.Exit(1)
	}

	gzipWriter.Close()
	gzipFile.Close()

	gzipInfo, _ := os.Stat(gzipPath)
	fmt.Printf("Wrote %s (%d bytes)\n", gzipPath, gzipInfo.Size())

	// Write version.json
	versionInfo := VersionInfo{
		Version:   db.Version,
		BuildTime: db.BuildTime,
		SHA256:    sha256Hex,
		Ranges:    len(allRanges),
		Size:      int64(len(msgpackData)),
		SizeGzip:  gzipInfo.Size(),
	}

	versionJSON, err := json.MarshalIndent(versionInfo, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing version info: %v\n", err)
		os.Exit(1)
	}

	versionPath := filepath.Join(outputDir, "version.json")
	if err := os.WriteFile(versionPath, versionJSON, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing version file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Wrote %s\n", versionPath)

	fmt.Printf("\nBuild complete!\n")
	fmt.Printf("  Version: %s\n", db.Version)
	fmt.Printf("  SHA256:  %s\n", sha256Hex)
	fmt.Printf("  Ranges:  %d\n", len(allRanges))
	fmt.Printf("  Size:    %d bytes (%.2f KB)\n", len(msgpackData), float64(len(msgpackData))/1024)
	fmt.Printf("  Gzipped: %d bytes (%.2f KB)\n", gzipInfo.Size(), float64(gzipInfo.Size())/1024)
}

func fetchProvider(jsonPath string) ([]SourceEntry, error) {
	url := fmt.Sprintf("%s/%s", baseURL, jsonPath)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var entries []SourceEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return entries, nil
}

// normalizeService normalizes service names for consistency
func normalizeService(service string) string {
	// Convert to lowercase for consistency
	s := strings.ToLower(service)

	// Map common variations
	switch s {
	case "amazon":
		return "AMAZON"
	case "ec2":
		return "EC2"
	case "s3":
		return "S3"
	case "cloudfront":
		return "CLOUDFRONT"
	case "google cloud":
		return "GOOGLE_CLOUD"
	default:
		return strings.ToUpper(service)
	}
}
