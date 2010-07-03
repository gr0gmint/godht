package dht

type Datastore interface {
    Set(Key, []byte)
    Get(Key) []byte
}
