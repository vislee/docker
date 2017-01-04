package main

import (
	"encoding/xml"
	"fmt"
)

type Resource struct {
	XMLName           xml.Name `xml:"resource"`
	Service           string   `xml:"service"`
	Item              string   `xml:"item"`
	SourceAssertError string   `xml:"error>assert>source"`
	InfoAssertError   string   `xml:"error>assert>info"`
	Timedelta         string   `xml:"timedelta"`
}

type Xml struct {
	XMLName xml.Name `xml:"xml"`
	Res     []Resource
}

func NewXml(service, item, infoMsg, errMsg, timedelta string) *Xml {
	x := &Xml{Res: make([]Resource, 0, 1)}
	x.AppendItem(service, item, infoMsg, errMsg, timedelta)
	return x
}

func (x *Xml) AppendItem(service, item, infoMsg, errMsg, timedelta string) {
	x.Res = append(x.Res, Resource{Service: service,
		Item:              item,
		SourceAssertError: errMsg,
		InfoAssertError:   infoMsg,
		Timedelta:         timedelta})
}

func (x *Xml) MarshalIndent() ([]byte, error) {
	b, e := xml.MarshalIndent(x, "  ", "  ")
	if e != nil {
		return nil, e
	}
	return []byte(fmt.Sprintf("%s%s\n", xml.Header, string(b))), nil
}

// func main() {
// 	x := &Xml{Res: make([]Resource, 0, 1)}
// 	// x := NewXml("sso", "", "", "22")
// 	// x.AppendItem("billing", "ok2", "err2", "2233")
// 	b, e := x.MarshalIndent()
// 	if e != nil {
// 		fmt.Printf("error: %s\n", e.Error())
// 		return
// 	}
// 	fmt.Printf("%s\n", string(b))
// 	return
// }
