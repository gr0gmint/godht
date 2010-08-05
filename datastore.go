package dht

import "bytes"
import "io"
import "fmt"

type Datastore interface {
    Set(Key, io.Reader)
    Get(Key) []byte
}

type SimpleDatastore struct {
    Data map[string]*SimpleEntry
}
type SimpleEntry struct  {
    Key Key
    Value *bytes.Buffer
}
func NewSimpleEntry() *SimpleEntry {
    s := new(SimpleEntry)
    s.Value = bytes.NewBufferString("")
    return s
}
func NewSimpleDatastore() *SimpleDatastore {
    s := new(SimpleDatastore)
    s.Data = make(map[string]*SimpleEntry)
    return s
}
func (this *SimpleDatastore) Get(key Key) []byte {
    if v, ok := this.Data[keytostring(key)]; ok {
        return v.Value.Bytes()
    }
    return nil
}
func (this *SimpleDatastore) Set(key Key, value io.Reader) {
        if _, ok := this.Data[keytostring(key)]; ok {
          return
        }
        e := NewSimpleEntry()
        
        e.Key = key
        b := make([]byte, 3000)
        for {
            n, err := value.Read(b)
            if err == nil {
                e.Value.Write(b[0:n])
            } else {break}
        }
        fmt.Printf("Storing something: %s\n", e.Value.Bytes())
        this.Data[keytostring(key)] = e
}

func keytostring(key Key) string {
    b := bytes.NewBuffer(key)
    return b.String()
}
