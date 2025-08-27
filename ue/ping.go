package ue

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// PingResult stores the results of a ping test
type PingResult struct {
	URL            string
	AverageLatency time.Duration
	PacketLoss     float64
	Error          error
}

// PingOptions configures the ping test
type PingOptions struct {
	Count    int           // Number of pings to send
	Timeout  time.Duration // Timeout for each ping
	Interval time.Duration // Interval between pings
}

// DefaultPingOptions returns default ping configuration
func DefaultPingOptions() PingOptions {
	return PingOptions{
		Count:    10,
		Timeout:  time.Second * 5,
		Interval: time.Millisecond * 500,
	}
}

// TestLatencyWithTCP tests latency using TCP connection
func TestLatencyWithTCP(url string, opts PingOptions) PingResult {
	hostname := extractHostname(url)
	if hostname == "" {
		return PingResult{
			URL:   url,
			Error: errors.New("invalid URL format"),
		}
	}

	var totalLatency time.Duration
	var successfulPings int

	for i := 0; i < opts.Count; i++ {
		start := time.Now()

		// Try to establish TCP connection
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s/ping", hostname), opts.Timeout)
		if err == nil {
			conn.Close()
			totalLatency += time.Since(start)
			successfulPings++
		}

		time.Sleep(opts.Interval)
	}

	if successfulPings == 0 {
		return PingResult{
			URL:   url,
			Error: errors.New("all ping attempts failed"),
		}
	}

	avgLatency := totalLatency / time.Duration(successfulPings)
	packetLoss := float64(opts.Count-successfulPings) / float64(opts.Count) * 100

	return PingResult{
		URL:            url,
		AverageLatency: avgLatency,
		PacketLoss:     packetLoss,
	}
}

// Helper function to extract hostname from URL
func extractHostname(urlStr string) string {
	// Remove protocol if present
	if strings.Contains(urlStr, "://") {
		parts := strings.Split(urlStr, "://")
		if len(parts) < 2 {
			return ""
		}
		urlStr = parts[1]
	}

	// Remove path and query parameters
	if strings.Contains(urlStr, "/") {
		urlStr = strings.Split(urlStr, "/")[0]
	}

	return urlStr
}

// Helper function to parse ping command output
func parsePingOutput(output string, url string) PingResult {
	// This is a simple implementation - you might want to make it more robust
	// based on your specific needs and OS output format
	lines := strings.Split(output, "\n")
	var avgLatency float64
	var packetLoss float64

	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "average") {
			// Extract average latency - format varies by OS
			// This is a simplified example
			fields := strings.Fields(line)
			for i, field := range fields {
				if strings.Contains(field, "ms") {
					fmt.Sscanf(fields[i-1], "%f", &avgLatency)
					break
				}
			}
		}
		if strings.Contains(strings.ToLower(line), "loss") {
			// Extract packet loss percentage
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.Contains(field, "%") {
					fmt.Sscanf(field, "%f", &packetLoss)
					break
				}
			}
		}
	}

	return PingResult{
		URL:            url,
		AverageLatency: time.Duration(avgLatency * float64(time.Millisecond)),
		PacketLoss:     packetLoss,
	}
}
