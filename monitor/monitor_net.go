package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type monitorResp struct {
	Code    int
	Message string
}

func main() {
	var mresp monitorResp

	urls := []string{"http://www.baidu.com/", "https://www.taobao.com/", "http://www.qq.com/"}
	for _, url := range urls {
		resp, err := mycurl(url)
		if err != nil {
			mresp.Code = 901
			mresp.Message = err.Error()
			break
		} else {
			mresp.Code = 200
			mresp.Message = fmt.Sprintf("curl %s", resp.Status)
			if resp.StatusCode != 200 || resp.StatusCode != 302 {
				mresp.Code = resp.StatusCode
				break
			}
		}
	}
	b, err := json.Marshal(&mresp)
	if err != nil {
		fmt.Printf(`{"Code": 900, "Message":%s}`, err.Error())
		return
	}

	fmt.Print(string(b))
	return
}

func mycurl(url string) (resp *http.Response, err error) {
	cli := &http.Client{
		Timeout: 3 * time.Second,
	}

	return cli.Get(url)
}
