package dht

import . "container/vector"
import "bytes"
type Datastore interface {
    Set(Key, []byte)
    Get(Key) []byte
}

type SimpleDatastore struct {
    Data *Vector
}
type SimpleEntry struct  {
    Key Key
    Value []byte
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
        m := (<-ch).(*SimpleEntry)
        if m == nil {return nil }
        if bytes.Compare(key, m.Key) == 0 {
            return m.Value
        }
    }
    return nil
}
func (this *SimpleDatastore) Set(key Key, value []byte) {
      e := new(SimpleEntry)
      e.Key = key
      e.Value = value
      this.Data.Push(e)  
}
