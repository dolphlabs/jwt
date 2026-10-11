package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type result struct {
	language string
	name     string
	latency  map[string][]int64
	batch    map[string]int64
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: summarize <named-result-file>...")
		os.Exit(2)
	}
	all := make([]result, 0, len(os.Args)-1)
	for _, arg := range os.Args[1:] {
		name, path, ok := strings.Cut(arg, "=")
		if !ok {
			fmt.Fprintf(os.Stderr, "bad result argument %q\n", arg)
			os.Exit(2)
		}
		item, err := readResult(name, path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
		all = append(all, item)
	}

	fmt.Println("run op samples p50_ns p99_ns batch_ops_per_sec")
	pooled := map[string]map[string][]int64{
		"Slang": {}, "Slang old": {}, "Slang new": {}, "Go": {},
	}
	batches := map[string]map[string][]float64{
		"Slang": {}, "Slang old": {}, "Slang new": {}, "Go": {},
	}
	for _, item := range all {
		for _, op := range []string{"S", "V"} {
			samples := item.latency[op]
			if len(samples) == 0 || item.batch[op] <= 0 {
				fmt.Fprintf(os.Stderr, "%s has no %s samples\n", item.name, op)
				os.Exit(1)
			}
			sorted := append([]int64(nil), samples...)
			sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
			rps := float64(len(samples)) * 1e9 / float64(item.batch[op])
			fmt.Printf("%s %s %d %d %d %.0f\n", item.name, op, len(samples),
				quantile(sorted, .50), quantile(sorted, .99), rps)
			pooled[item.language][op] = append(pooled[item.language][op], samples...)
			batches[item.language][op] = append(batches[item.language][op], rps)
		}
	}
	fmt.Println("pooled op samples p50_ns p99_ns")
	for _, lang := range []string{"Slang old", "Slang new", "Slang", "Go"} {
		for _, op := range []string{"S", "V"} {
			samples := pooled[lang][op]
			if len(samples) == 0 {
				continue
			}
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			fmt.Printf("%s %s %d %d %d\n", lang, op, len(samples),
				quantile(samples, .50), quantile(samples, .99))
		}
	}
	fmt.Println("median batch ops_per_sec")
	for _, lang := range []string{"Slang old", "Slang new", "Slang", "Go"} {
		for _, op := range []string{"S", "V"} {
			values := batches[lang][op]
			if len(values) == 0 {
				continue
			}
			sort.Float64s(values)
			mid := len(values) / 2
			median := values[mid]
			if len(values)%2 == 0 {
				median = (values[mid-1] + values[mid]) / 2
			}
			fmt.Printf("%s %s %.0f\n", lang, op, median)
		}
	}
}

func readResult(name, path string) (result, error) {
	item := result{name: name, latency: map[string][]int64{}, batch: map[string]int64{}}
	if strings.HasPrefix(name, "slangold") {
		item.language = "Slang old"
	} else if strings.HasPrefix(name, "slangnew") {
		item.language = "Slang new"
	} else if strings.HasPrefix(name, "slang") {
		item.language = "Slang"
	} else if strings.HasPrefix(name, "go") {
		item.language = "Go"
	} else {
		return item, fmt.Errorf("result name must begin with slang or go")
	}
	file, err := os.Open(path)
	if err != nil {
		return item, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 3 && fields[0] == "B" {
			value, parseErr := strconv.ParseInt(fields[2], 10, 64)
			if parseErr != nil {
				return item, parseErr
			}
			item.batch[fields[1]] = value
		} else if len(fields) == 2 && (fields[0] == "S" || fields[0] == "V") {
			value, parseErr := strconv.ParseInt(fields[1], 10, 64)
			if parseErr != nil {
				return item, parseErr
			}
			item.latency[fields[0]] = append(item.latency[fields[0]], value)
		}
	}
	return item, scanner.Err()
}

func quantile(sorted []int64, q float64) int64 {
	idx := int(float64(len(sorted)-1) * q)
	return sorted[idx]
}
