package ue

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
)

func sendGetRequest(baseUrl, api string, query map[string]string, client *http.Client) ([]byte, error) {
	u, err := url.Parse(baseUrl + api)
	if err != nil {
		panic(err)
	}

	q := u.Query()
	for k, v := range query {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		log.Fatal("Failed to send request:", u.String(), err)
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal("Failed to close response body:", err)
		}
	}(resp.Body)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Failed to read response body:", err)
		return nil, err
	}

	return respBody, nil
}

func sendPostRequest(baseUrl, api string, body []byte, client *http.Client) ([]byte, error) {
	u, err := url.Parse(baseUrl + api)
	if err != nil {
		panic(err)
	}

	resp, err := client.Post(u.String(), "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Fatal("Failed to send request:", u.String(), err)
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal("Failed to close response body:", err)
		}
	}(resp.Body)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Failed to read response body:", err)
		return nil, err
	}

	return respBody, nil
}
