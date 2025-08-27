package main

import (
	"fmt"
	"ppakma/ue"
)

func main() {
	fmt.Println("Hello, World!")
	// test throughput
	//ue.BenchmarkRequests()
	//
	//stat1 := ue.RunBenchmark2POS(10)
	//stat2 := ue.RunBenchmarkAmortized2POS(10)
	//
	//fmt.Println("=====================================")
	//fmt.Println("Benchmark 2POS")
	//fmt.Println(stat1)
	//fmt.Println("Benchmark Amortized 2POS")
	//fmt.Println(stat2)
	//stat := ue.RunBenchmarkProtocol(1, "https://127.0.0.1:18080", "https://127.0.0.1:18081")
	stat := ue.RunBenchmarkAmortizedProtocol(1, "https://127.0.0.1:18080", "https://127.0.0.1:18081")
	//stat := ue.RunBenchmarkNormalProtocol(1, "https://127.0.0.1:18080", "https://127.0.0.1:18081")

	fmt.Println(stat)

}
