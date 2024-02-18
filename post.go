/*
 * CyberSupervisor GOpost
 * Copyright (C) 2024 Rob Rogers  rob@ontariohighspeed.ca
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License 2.1
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */

package main

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha512"
    "encoding/hex"
    "encoding/json"
    "html"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "strings"
)

type LogSource struct {
    Path    string `json:"path"`
    PostVar string `json:"postVar"`
}

type Config struct {
    URL        string      `json:"url"`
    LogSources []LogSource `json:"logSources"`
    HMACSecret string      `json:"hmacsecret"`
}

func LoadConfig() (Config, error) {
    var config Config
    paths := []string{"/etc/cybersupervisor/post.cfg", "post.cfg"}
    for _, path := range paths {
        data, err := ioutil.ReadFile(path)
        if err == nil {
            if json.Unmarshal(data, &config) == nil {
                return config, nil
            }
        }
    }
    return config, os.ErrNotExist
}

func ComputeHMAC512(message, key string) string {
    h := hmac.New(sha512.New, []byte(key))
    h.Write([]byte(message))
    return hex.EncodeToString(h.Sum(nil))
}

func sanitizeData(data []byte) ([]byte, error) {
    var rawJSON interface{}
    if err := json.Unmarshal(data, &rawJSON); err != nil {
        return nil, err
    }

    sanitizedJSON := sanitize(rawJSON)
    return json.Marshal(sanitizedJSON)
}

func sanitize(value interface{}) interface{} {
    switch v := value.(type) {
    case map[string]interface{}:
        for key, val := range v {
            v[key] = sanitize(val)
        }
    case []interface{}:
        for i, val := range v {
            v[i] = sanitize(val)
        }
    case string:
        return html.EscapeString(v)
    }
    return value
}

func PostData(url, postVar, logData, hmacSecret string) error {
    signature := ComputeHMAC512(logData, hmacSecret)
    postData := map[string]string{
        postVar:    logData,
        "signature": signature,
    }
    postDataBytes, err := json.Marshal(postData)
    if err != nil {
        return err
    }

    client := &http.Client{}
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(postDataBytes))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    return nil
}

func main() {
    config, err := LoadConfig()
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    for _, source := range config.LogSources {
        logData, err := ioutil.ReadFile(source.Path)
        if err != nil {
            log.Printf("Failed to read log file from %s: %v", source.Path, err)
            continue
        }

        sanitizedData, err := sanitizeData(logData)
        if err != nil {
            log.Printf("Failed to sanitize log data from %s: %v", source.Path, err)
            continue
        }

        err = PostData(config.URL, source.PostVar, string(sanitizedData), config.HMACSecret)
        if err != nil {
            log.Printf("Failed to post data: %v", err)
        }
    }
}

