package dht

import . "container/vector"
import "bytes"
import "io"
import "fmt"

type Datastore interface {
    Set(Key, io.Reader)
    Get(Key) []byte
}

type SimpleDatastore struct {
    Data *Vector
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
    s.Data = new(Vector)
    return s
}
func (this *SimpleDatastore) Get(key Key) []byte {
    ch := this.Data.Iter()
    for {
        if closed(ch) {return nil}
        n := (<-ch)
        if n == nil {return nil}
        m := n.(*SimpleEntry)
        if bytes.Compare(key, m.Key) == 0 {
            return m.Value.Bytes()
        }
    }
    return nil
}
func (this *SimpleDatastore) Set(key Key, value io.Reader) {

      ch := this.Data.Iter()
      for {
        if closed(ch) {break}
        m := <-ch
        if m == nil {break}
        if bytes.Compare(m.(*SimpleEntry).Key, key) == 0 {fmt.Printf("Already got this value\n"); return }
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
      this.Data.Push(e)  
}
