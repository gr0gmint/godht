package dht

/**********TEMPLATE FOR HOT FUNCTION*********
    h := NewHot(func(shared map[string]interface{}){
        self := shared["self"].(*GenericHot)
    })
    this.QueryHot(h)
    answer:=<-h.Answer
*********************************************/


type Hot interface { //Hot code "swapping"
    Unpack(map[string]interface{})
}
type NamedHot interface {
    Hot
    Type() string
}
type GenericHot struct {
    F func(map[string]interface{})
    Answer chan interface{}
}
func NewHot(f func(map[string]interface{})) *GenericHot {
    h := new(GenericHot)
    h.F = f
    h.Answer = make(chan interface{})
    return h
}
func (this *GenericHot) Unpack(data map[string]interface{}) {
    this.F(data)
}
type HotRoutine struct {
    HotChan chan Hot
    hotlock bool
}
func (this *HotRoutine) QueryHot(h Hot) {
    //if !this.hotlock {
     this.HotChan<-h
    //} else { //We're already in another hot, which means the hot called another hot
    //    shared := make(map[string]interface{})
    //    shared["self"] = h
    //    go h.Unpack(shared)
    //}

}

func (this *HotRoutine) HotStart() {
    this.hotlock=false
    this.HotChan = make(chan Hot)
    for {
        h := <-this.HotChan
        shared := make(map[string]interface{})
        shared["self"] = h
        this.hotlock=true
        h.Unpack(shared)
        this.hotlock=false
    }
}
