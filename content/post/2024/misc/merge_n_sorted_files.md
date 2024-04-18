---
title: "Golang: Merging N sorted files to a single sorted file"
date: 2024-04-15T01:24:55-05:00
url: "/misc/golang/merging_n_sorted_files_to_a_sorted_file"
Description: |
    Merging an arbitrary number of sorted files into a single sorted file using Golang.
type: posts
sidebar_toc: true
categories:
 - programming
tags:
 - golang
---

## Background

Given a directory of sorted files, join them into a single file that is also sorted.

Requirements:

* Don't load all/any files entirely into memory at once.

## Solution

### rough outline

* get a reader on all the files in a dir
* grab just first line from all of them
* take the smallest, write line to open output file handler
* read the next line from the file which we determined was the smallest
* repeat until we've parsed through everything

### code

```golang
package main

import (
    "bufio"
    "fmt"
    "io"
    "log"
    "os"
    "path/filepath"
    "runtime"
)

func PrintMemUsage(msg string) {
    var m runtime.MemStats
    fmt.Printf("==== %s\n", msg)
    runtime.ReadMemStats(&m)
    fmt.Printf("Alloc = %v MiB", m.Alloc/1024/1024)
    fmt.Printf("\tTotalAlloc = %v MiB", m.TotalAlloc/1024/1024)
    fmt.Printf("\tSys = %v MiB", m.Sys/1024/1024)
    fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func ReadNextScannerLine(sc *bufio.Scanner) (line string, err error) {
    foundText := sc.Scan()
    if foundText {
    return sc.Text(), nil
    } else {
    return "", io.EOF
    }
}

func main() {
    PrintMemUsage("init")

    outFile, err := os.Create("sorted")
    if err != nil {
        log.Fatal(err)
    }
    defer outFile.Close()

    var dictionary = map[string]*bufio.Scanner{}
    var valuesDict = map[string]string{}

    // List the generated flowlogs files
    generatedDir := "generated"
    dirPath, _ := filepath.Abs(generatedDir)
    files, err := os.ReadDir(generatedDir)
    if err != nil {
        log.Fatal(err)
    }

    // Build the map of files to merge
    for _, file := range files {
        fullPath := filepath.Join(dirPath, file.Name())
        fileIO, err := os.OpenFile(fullPath, os.O_RDWR, 0644)
        if err != nil {
            panic(err)
        }
        defer fileIO.Close()

        dictionary[fullPath] = bufio.NewScanner(bufio.NewReader(fileIO))
    }

    // Read the initial lines
    smallest := ""
    var slurped string

    for k, v := range dictionary {
        line, err := ReadNextScannerLine(v)
        if err != nil {
            if err == io.EOF {
                fmt.Println("Removing file from dictionary as fully processed")
                delete(dictionary, k)
            } else {
                log.Fatal(err)
            }
        }
        valuesDict[k] = line

        if smallest == "" {
            smallest = line
        }

        if line <= smallest {
            smallest = line
            slurped = k
        }
    }
    // Write to sorted
    fmt.Fprintln(outFile, smallest)
    smallest = ""

    // need to read the next value from slurped, then compare against all others, and
    // repeat until we've fully processed all files
    for {
        nextLine, err := ReadNextScannerLine(dictionary[slurped])
        if err != nil {
            if err == io.EOF {
                delete(dictionary, slurped)
                delete(valuesDict, slurped)
                if len(dictionary) == 0 {
                    break
                }
                smallest = ""
            } else {
                log.Fatal(err)
            }
        } else {
            valuesDict[slurped] = nextLine
        }

        for k, v := range valuesDict {
            if smallest == "" {
                smallest = v
            }

            if v <= smallest {
                smallest = v
                slurped = k
            }
        }
        fmt.Fprintln(outFile, smallest)
        smallest = ""
    }
    PrintMemUsage("after sorting")
}
```

## Results

Against a directory of 21 files of ~76MB each, totalling just over 6 million lines:

```bash
λ  go build -ldflags "-s -w" main.go
```

```text
λ  time ./main

==== init
Alloc = 0 MiB   TotalAlloc = 0 MiB      Sys = 6 MiB     NumGC = 0
==== after sorting
Alloc = 1 MiB   TotalAlloc = 1766 MiB   Sys = 11 MiB    NumGC = 514

./main  4.33s user 11.09s system 96% cpu 15.970 total
```

```bash
λ  du -h <input dir>
1.6G    <input dir>

λ  du -h <output_file>
1.6G    <output_file>

λ  wc -l <output_file>
6090000 <output_file>
```
