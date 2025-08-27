package ue

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// RequestType defines the type of HTTP request
type RequestType string

// ParameterSet represents a set of test parameters
type ParameterSet struct {
	Name       string
	Parameters map[string]interface{} // Using interface{} to support different value types
}

// BenchmarkConfig holds the configuration for the benchmark test
type BenchmarkConfig struct {
	BaseURL          string
	RequestType      string
	Concurrency      int
	ConcurrentParams int
	Duration         time.Duration
	ParamSets        []ParameterSet
	CommonHeader     map[string]string
}

// Result represents the benchmark results
type Result struct {
	ParamSetName       string
	RequestType        RequestType
	TotalRequests      int64
	SuccessfulRequests int64
	FailedRequests     int64
	TotalLatency       time.Duration
	AverageLatency     time.Duration
	RequestsPerSecond  float64
}

type registerContext struct {
	uid      string
	Username string
	Supi     string
	// post request body
	HNPostRequest1 []byte
	HNPostRequest2 []byte
	AFPostRequest  []byte
	// response
	HNResponse1 []byte
	HNResponse2 []byte
	HNResponse3 []byte
	AFResponse  []byte
}

var (
	HNURL = "https://123.57.249.198"
	AFURL = "https://47.94.233.15"
)

var (
	concurrency                        = 1
	requestSize                        = 100
	registerContexts []registerContext = make([]registerContext, 100)
)

func BenchmarkRequests() {
	// GET request configuration
	AF1Config := BenchmarkConfig{
		BaseURL:          AFURL + "/api/af/reg/request",
		RequestType:      "GET",
		Concurrency:      1,
		ConcurrentParams: 1,
		Duration:         5 * time.Second,
		ParamSets:        generateRegisterAF1TestParams(),
		CommonHeader: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
	}

	HN1Config := BenchmarkConfig{
		BaseURL:          HNURL + "/api/hn/reg/request",
		RequestType:      "GET",
		Concurrency:      1,
		ConcurrentParams: 1,
		Duration:         5 * time.Second,
		ParamSets:        generateRegisterHN1TestParams(),
		CommonHeader: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
	}

	// POST request configuration
	//postConfig := BenchmarkConfig{
	//	BaseURL:     "http://example.com/api/filter",
	//	RequestType: POST,
	//	Concurrency: 10,
	//	Duration:    5 * time.Second,
	//	ParamSets: []ParameterSet{
	//		{
	//			Name: "Simple-Filter",
	//			Parameters: map[string]interface{}{
	//				"filters": map[string]interface{}{
	//					"category": "electronics",
	//					"limit":    20,
	//					"offset":   0,
	//				},
	//			},
	//		},
	//		{
	//			Name: "Complex-Filter",
	//			Parameters: map[string]interface{}{
	//				"filters": map[string]interface{}{
	//					"categories": []string{"electronics", "accessories"},
	//					"priceRange": map[string]float64{
	//						"min": 100.0,
	//						"max": 1000.0,
	//					},
	//					"brands": []string{"apple", "samsung", "google"},
	//					"specifications": map[string]interface{}{
	//						"storage":  []int{64, 128, 256},
	//						"color":    []string{"black", "silver"},
	//						"inStock":  true,
	//						"shipping": "free",
	//					},
	//				},
	//				"sorting": map[string]string{
	//					"field":     "price",
	//					"direction": "desc",
	//				},
	//				"pagination": map[string]int{
	//					"page":     1,
	//					"pageSize": 20,
	//				},
	//			},
	//		},
	//	},
	//	CommonHeader: map[string]string{
	//		"Content-Type": "application/json",
	//		"Accept":       "application/json",
	//	},
	//}

	// Run benchmarks for both configurations
	configs := []BenchmarkConfig{AF1Config, HN1Config}
	for _, config := range configs {
		startTime := time.Now()
		results := runConcurrentBenchmark(config)
		fmt.Printf("\nTotal time taken for benchmark: %v\n", time.Since(startTime))
		for _, result := range results {
			printResults(result)
		}

	}
}

func runConcurrentBenchmark(config BenchmarkConfig) []Result {
	results := make([]Result, len(config.ParamSets))
	var wg sync.WaitGroup
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        500,
			MaxIdleConnsPerHost: 500,
			IdleConnTimeout:     90 * time.Second,
			TLSClientConfig:     tlsConfig,
		},
	}

	// Concurrently test each parameter set
	for i := 0; i < len(config.ParamSets); i += config.ConcurrentParams {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()

			var paramWg sync.WaitGroup
			var paramResults []Result

			end := start + config.ConcurrentParams
			if end > len(config.ParamSets) {
				end = len(config.ParamSets)
			}

			for j := start; j < end; j++ {
				paramWg.Add(1)
				go func(index int) {
					defer paramWg.Done()
					paramResults = append(paramResults, runParameterBenchmark(config, config.ParamSets[index], client))
				}(j)
			}

			paramWg.Wait()

			// Aggregate the results from the concurrent parameter sets
			for j, result := range paramResults {
				results[start+j] = result
			}
		}(i)
	}

	wg.Wait()
	return results
}

func runParameterBenchmark(config BenchmarkConfig, paramSet ParameterSet, client *http.Client) Result {
	var (
		result      Result
		resultMutex sync.Mutex
		workerWg    sync.WaitGroup
		done        = make(chan bool)
	)

	result.ParamSetName = paramSet.Name
	startTime := time.Now()

	// Start timer to stop the benchmark after duration
	go func() {
		time.Sleep(config.Duration)
		close(done)
	}()

	// Start worker goroutines for this parameter set
	for j := 0; j < config.Concurrency; j++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()

			for {
				select {
				case <-done:
					return
				default:
					req, err := buildRequest(config, paramSet)
					if err != nil {
						continue
					}

					startReq := time.Now()
					resp, err := client.Do(req)
					latency := time.Since(startReq)

					resultMutex.Lock()
					result.TotalRequests++
					result.TotalLatency += latency
					if err != nil || resp.StatusCode >= 400 {
						result.FailedRequests++
					} else {
						result.SuccessfulRequests++
					}
					resultMutex.Unlock()

					if resp != nil {
						resp.Body.Close()
					}
				}
			}
		}()
	}

	workerWg.Wait()

	// Calculate final results for this parameter set
	totalDuration := time.Since(startTime)
	result.RequestsPerSecond = float64(result.TotalRequests) / totalDuration.Seconds()
	if result.TotalRequests > 0 {
		result.AverageLatency = result.TotalLatency / time.Duration(result.TotalRequests)
	}

	return result
}

func buildRequest(config BenchmarkConfig, paramSet ParameterSet) (*http.Request, error) {
	if config.RequestType == "GET" {
		req, err := http.NewRequest(string(config.RequestType), config.BaseURL, nil)
		if err != nil {
			return nil, err
		}

		// Add query parameters
		q := req.URL.Query()
		for key, value := range paramSet.Parameters {
			q.Add(key, fmt.Sprintf("%v", value))
		}
		req.URL.RawQuery = q.Encode()

		// Add headers
		for key, value := range config.CommonHeader {
			req.Header.Add(key, value)
		}

		return req, nil
	} else if config.RequestType == "POST" {
		jsonBody, err := json.Marshal(paramSet.Parameters)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequest(string(config.RequestType), config.BaseURL, bytes.NewBuffer(jsonBody))
		if err != nil {
			return nil, err
		}

		// Add headers
		for key, value := range config.CommonHeader {
			req.Header.Add(key, value)
		}

		return req, nil
	}

	return nil, fmt.Errorf("unsupported request type: %s", config.RequestType)
}

func buildGETRequest(config BenchmarkConfig, paramSet ParameterSet) (*http.Request, error) {
	req, err := http.NewRequest(string(config.RequestType), config.BaseURL, nil)
	if err != nil {
		return nil, err
	}

	// Add query parameters
	q := req.URL.Query()
	for key, value := range paramSet.Parameters {
		q.Add(key, fmt.Sprintf("%v", value))
	}
	req.URL.RawQuery = q.Encode()

	// Add headers
	for key, value := range config.CommonHeader {
		req.Header.Add(key, value)
	}

	return req, nil
}

func buildPOSTRequest(config BenchmarkConfig, paramSet ParameterSet) (*http.Request, error) {
	jsonBody, err := json.Marshal(paramSet.Parameters)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(string(config.RequestType), config.BaseURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	// Add headers
	for key, value := range config.CommonHeader {
		req.Header.Add(key, value)
	}

	return req, nil
}

func generateRegisterAF1TestParams() []ParameterSet {
	for i := 0; i < requestSize; i++ {
		// Generate test parameters
		uid := GenerateUID()
		username := "NAME--" + uid
		supi := "imsi-" + GenerateSUPI()
		registerContexts[i] = registerContext{uid: uid, Username: username, Supi: supi}
	}
	paramSet := make([]ParameterSet, requestSize)
	for i := 0; i < requestSize; i++ {
		paramSet[i] = ParameterSet{
			Name: fmt.Sprintf("Test-Reg-AF01-%d", i),
			Parameters: map[string]interface{}{
				"uid":      registerContexts[i].uid,
				"username": registerContexts[i].Username,
			},
		}
	}

	return paramSet
}

func generateRegisterHN1TestParams() []ParameterSet {
	paramSet := make([]ParameterSet, requestSize)
	for i := 0; i < requestSize; i++ {
		paramSet[i] = ParameterSet{
			Name: fmt.Sprintf("Test-Reg-HN01-%d", i),
			Parameters: map[string]interface{}{
				"supi": registerContexts[i].Supi,
			},
		}
	}

	return paramSet
}

func printResults(result Result) {
	fmt.Printf("\nBenchmark Results for %s - %s:\n", result.RequestType, result.ParamSetName)
	fmt.Printf("Total Requests: %d\n", result.TotalRequests)
	fmt.Printf("Successful Requests: %d\n", result.SuccessfulRequests)
	fmt.Printf("Failed Requests: %d\n", result.FailedRequests)
	fmt.Printf("Average Latency: %v\n", result.AverageLatency)
	fmt.Printf("Requests/Second: %.2f\n", result.RequestsPerSecond)
}
