package dht

import . "gocon"
import . "container/vector"
import "net"
import "os"
import "crypto/rsa"
import "crypto/x509"
import "crypto/rand"
import random "rand"
import "time"


const (
    k = 8
    a = 3
    b = 160
    tExpire = 86400
    tRefresh = 3600
    tReplicate = 3600
    tRepublish = 86400
    MAXPKTSIZE = 4096
    MAXSTORESIZE = 64000

)
type Key []byte
func Distance(key1 Key,key2 Key) Key {
}

type NodeDescriptor {
    Addr *net.UDPAddr
    Behindnat bool
    Nodeid []byte
}

type NodeHandler struct {
    ProtoHandler
}

type Bucket struct {
    Nodes Vector // []*NodeDescriptor   
}
type Nodeid []byte

type Node struct {
    HotRoutine
    Buckets [b]Bucket
    Nodeid Nodeid
    Reachable bool
    
}

type Listener struct {
    Node *Node
    Port int
}


func NewMsgId() int32 {
    return random.Int31()
}



type ConnHandler struct {
    HotRoutine
    Node *Node
    Conn *net.UDPConn
    Buffer []byte
    IdMap map[int32]chan hdr_n_data
    Default chan hdr_n_data
    RecpPublickey *rsa.PublicKey
    
}

type hdr_n_data {
    header *Header
    data []byte
}


func NewConnHandler(node *Node, conn *net.UDPConn) *ConnHandler {
    c := new(ConnHandler) 
    c.Conn = conn
    c.Node = node
    return c
}
func (this *ConnHandler) RemoveFromBucket()

func (this *ConnHandler) Start() {
    defer this.RemoveFromBucket()
    go this.HotStart()
    
    this.Buffer = make([]byte, 10000)
    this.Default = make(chan []byte)
    go func()  {
        for {
            n, err := this.Conn.Read(this.Buffer)
            if err != nil {continue}
            newbuf := make([]byte, n)
            copy(newbuf, this.Buffer)
            header,_,err := this.DecodePacket(newbuf)
            
            if *header.Part >  0 {
                if this.IdMap[*header.Msgid] == nil {
                    this.IdMap[*header.Msgid] = make(chan hdr_n_data)
                }
                go func() { this.IdMap[*header.Msgid]<-newbuf}()
            } else {
                go func() { this.Default <- newbuf }
            }
            
            
        }
    }()
}
func (this *ConnHander) getRecpPublickey() bool {
    if this.RecpPublicKey != nil {  
        return true
    } else {
        m := NewGetPublicKey()
        mdata := proto.Marshal(m) {
        }
    }
}

func (this *ConnHandler) Read(msgid int32)([]byte, os.Error) {
    h := NewHot(func(shared map[string]interface{}){     
        self := shared["self"].(*GenericHot)
        if msgid == 0 {
            data := <-this.Default
            header,mdata,err := this.DecodePacket(data)
            if err != nil { self.Answer<-hdr_n_data{nil,nil}} else {
              self.Answer<-hdr_n_data{header,mdata}
            }
            return
        } else {
            if this.IdMap[msgid] == nil { this.IdMap[msgid] = make(chan []byte) }
            data :=  <-this.IdMap[msgid]
                        header,mdata,err := this.DecodePacket(data)
            if err != nil { self.Answer<-hdr_n_data{nil,nil}} else {
              self.Answer<-hdr_n_data{header,mdata}
            }
            return
        }   
        
    })
    this.queryHot(h)
    answer:=(<-h.Answer).(hdr_n_data)
   return answer.header,answer.data
}

func (this *ConnHandler) Send(data []byte, t, id,part  int32, first,hmac bool) {
    pdata := this.EncodePacket(data,t,id,part,first,hmac) 
    this.Conn.Write(pdata)   
}

func (this *ConnHandler) Ping() bool {
    msgid := NewMsgId()
    ping_packet := NewPing()
    ping_data,_ := proto.Marshal(ping_packet)
    packet := this.EncodePacket(ping_data, PktType_PING, msgid, 0, false)
    this.Conn.SetReadTimeout(5000000000)
    header,data := this.Read(msgid)
    this.Conn.SetReadTimeout(0)
    if header == nil or data == nil {
        return false
    }
    if *header.Type == PktType_PONG {
        return true
    }
    return false
}

func (this *ConnHandler) Store(key Key, value []byte) bool {
    msgid := NewMsgId()
    
    //Find out if recipient is new (Needs public key)
    
    m := NewStore()
    m.Key = key
    m.Value = value
    if len(value) > 3000 {  //Split it up in multiple packets
    } else {
        mdata,_ := proto.Marshal(m)
        pdata := this.Send(mdata,PktType_STORE, msgid, 0,false, true)
    }
    

    
}

func NewNode(udpport int) *Node {
    n := new(Node)
    return n
}


func NewListener(node *Node, port int) {
    l := new(Listener)
    l.Node = node
    l.Port = port
    return l
}

func (this *Listener) Listen() {
    laddr,_ := net.ResolveUDPAddr("0.0.0.0:"+string(this.Port))
    for {
        conn, err := net.ListenUDP("udp", laddr)
        if err != nil {
            continue;
        }
        handler := NewConnHandler(this.Node, conn)
    }
}


func (this *Node) Bootstrap(port int, knownhost *net.UDPAddr) bool {
    random.Seed(time.Nanoseconds())

    //Establish private key
    f, err := os.Open("~/.godht/private_key", os.O_RDONLY, 0666) 
    if err != nil {
        os.Mkdir("~/.godht")
        f,_ = os.Open("~/.godht/private_key", os.O_WRONLY, 0644)
        fmt.Printf("Generating key... \n")
        pk,_ := GenerateKey(rand.Reader, 2048)
        pkdata := MarshalPKCS1PrivateKey(pk)
        f.Write(pkdata)
        f.Close()
        f,_ = os.Open("~/.godht/private_key", os.O_RDONLY, 0666)
    }
    fi := os.Stat("~/.godht/private_key")
    size := int(fi.Size)
    pkdata s:= make([]byte, size)
    f.Read(pkdata)

    keypair:=  x509.ParsePKCS1PrivateKey(pkdata)
    
    /*
    //Find out if reachable
    this.Reachable = true
    tmpaddr,_ := net·ResolveUDPAddr("0.0.0.0:5001")
    tmpconn,_ := net.DialUDP("udp", tmpaddr, knownhost)

    m := NewCheckReachability()
    mdata := proto.Marshal(m)
    tmpdata := EncodePacket(mdata, PktType_CHECKREACHABILITY, 0, false, nil)
    tmpconn.Send(tmpdata)
    
    tmpconn.SetReadTimeout(5000000000)
    _,_,err := tmphandler.ReadMsg()
    if err != nil {
        this.Reachable = false
    }
    tmpconn.Close()
    */
    
    
    //Start the listener on port 5000
    l := NewListener(this, 5000)
    l.Listen()
    
    //Connect to known host
    laddr,_ := net·ResolveUDPAddr("0.0.0.0:5000")
    conn,_ := net·DialUDP("udp", laddr, knownhost)
    c := NewConnHandler(this, conn)
    c.FindNode
    
}

