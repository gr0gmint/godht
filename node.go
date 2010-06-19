package dht

import . "gocon"
import . "container/vector"
import "net"
import "os"
import "crypto/rsa"
import "crypto/x509"
import "crypto/rand"
import "crypto/sha1"
import random "rand"
import "time"
import "encoding/binary"
import "bytes"

const (
    K = 20
    Alpha = 3
    B = 160
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

type InNodeDescriptor { /* In = internal */
    Addr *net.UDPAddr
    Behindnat bool
    Nodeid []byte
    Connhandler *ConnHandler
    PublicKey *rsa.PublicKey
    Bucket *Bucket
}

type NodeHandler struct {
    ProtoHandler
}

type Bucket struct {
    Node *Node
    v Vector 
}
func NewBucket(n *Node) b *Bucket {
    b  new(Bucket)
    b.Node = n
    return
}
func (this *Bucket) Len() int {
    return this.v.Len()
}
func (this *Bucket) Less(i,j int) bool {
    distance1 := Distance(this.At(i).Nodeid, this.Node.Nodeid)
    distance2 := Distance(this.At(j).Nodeid, this.Node.Nodeid)
    return distance1.Less(distance2)
}
func (this *Bucket) At(i int) *InNodeDescriptor {
    return this.v.At(i).(*InNodeDescriptor) 
}
func (this *Bucket) Swap(i,j int) {
    this.v.Swap(i,j)
}
func (this *Bucket) Push(node *InNodeDescriptor) {
    this.v.Push(node)
}

func (this *Bucket) Pop() *InNodeDescriptor {
    return this.v.Pop().(*InNodeDescriptor)
}


func (this *Bucket) Cut(i,j int) *InNodeDescriptor {
    this.v.Pop().(*InNodeDescriptor)
}
type Node struct {
    HotRoutine
    Buckets map[int]
    Nodeid Key
    Reachable bool
    Keypair *rsa.PrivateKey
}

type Listener struct {
    Node *Node
    Port int
}


type ConnHandler struct {
    HotRoutine
    Node *Node
    RecpNode *InNodeDesc
    Conn *net.UDPConn
    Buffer []byte
    IdMap map[int32]chan hdr_n_data
    Default chan hdr_n_data
    FirstPacketSent bool //If the repicient needs the publickey
    NodeIsAdded bool //If the node is added to bucket
}



func NewMsgId() int32 {
    return random.Int31()
}

func BucketNo(d Distance) uint {
	var basebitnr uint = 0

	for _, b := range d {
		if b == 0 {
			basebitnr += 8
			continue
		}
		var bitnr uint = 0
		for i := 0; i < 8; i++ {
			if (b & (0x80 >> bitnr)) != 0 {
				return basebitnr + bitnr
			}
			bitnr++
		}
	}

	return basebitnr
}

func XOR(a, b []byte) Key {
	l := len(a)
	if l != len(b) {
		return nil
	}

	d := make(Distance, l)

	for i := 0; i < l; i++ {
		d[i] = a[i] ^ b[i]
	}

	return d
}


func (a Key) Less(b Key) bool {
	if len(a) != len(b) {
        return false
	}
	for i, ea := range a {
		eb := b[i]
		switch {
		case ea < eb:
			return true
		case ea > eb:
			return false
		default:
		}
	}
	return false
}



type hdr_n_data {
    header *Header
    data []byte
}


func (this *Node) DecodePacket(data []byte) (*Header,[]byte, os.Error) {
    //Read header first
    var hdrlen uint32
    var datalen uint32
    if err != nil  {
        return nil,nil,addr,err
    }
    err = binary.Read(data[0:4], binary.BigEndian, &hdrlen)
        if err != nil { return nil,nil,addr,err }
    err = binary.Read(data[4:8], binary.BigEndian, &datalen)
        if err != nil { return nil,nil,addr,err }
    if !(hdrlen < 512 && datalen <= 4096 ) {
        return nil,nil,addr,os.ENOMEM
    }
    hdrdata := make(Buf, hdrlen)
    newdata := make(Buf, datalen)
    copy(hdrdata,tmp)
    header := NewHeader()
    err = proto.Unmarshal(hdrdata, header)
    if err != nil {
        return nil,nil,addr,err
    }
    copy(newdata,tmp)
    
    
    return header, newdata,nil
}
 
func (this *Node) EncodePacket(data []byte, t,id,part int32, first,hmac,encrypted bool) []byte {
        header := NewHeader()
        header.Type = proto.Int32(t)
        header.Msgid = proto.Int32(id)
        hdrdata,err := proto.Marshal(header)
        if err != nil {
            fmt.Printf("%s\n", err)
            return
        }
        hdrlen := uint32(len(hdrdata))
        datalen :=  uint32(len(data))
        buffer := 8+hdrlen+datalen
        binary.Write(buffer, binary.BigEndian, [2]uint32{hdrlen,datalen})
        copy(buffer[8:8+len(hdrdata)],hdrdata)
        copy(buffer[8+len(hdrdata):8+len(hdrdata)+len(data)], data
        return buffer
}



func NewConnHandler(node *Node, conn *net.UDPConn) *ConnHandler {
    c := new(ConnHandler) 
    c.Conn = conn
    c.Node = node
    return c
}


func (this *ConnHandler) RemoveFromBucket() {
    
}

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

func (this *ConnHandler) Read(msgid int32)(*Header, []byte) {
    h := NewHot(func(shared map[string]interface{}){     
        self := shared["self"].(*GenericHot)
        

/*        
        
        //see if we have publickey, if not, require that it is included in the header
        if this.RecpNode.PublicKey == nil {
            
        }
  */      
        if msgid == 0 {
            data := <-this.Default
            header,mdata,err := this.DecodePacket(data)
            if err != nil { self.Answer<-hdr_n_data{nil,nil}} else {
              //If this is some of the first packets received  - needs perhaps to be added to bucket
                if !this.NodeIsAdded {
                    //HMAC and publickey and nodedescriptor objects are mandatory for this first header. If not included, ignore
                    if header.Hmac == nil || header.From == nil || header.From.PublicKey == nil {
                        self.Answer<-hdr_n_data{nil,nil}
                        return
                    } else {
                        //Add nodedescriptor to bucket
                       
                        desc := new(InNodeDescriptor)
                        desc.Connhandler = this
                        desc.Addr = this.Conn.RemoteAddr()
                        desc.Behindnat = *header.From.Behindnat
                        desc.Nodeid = header.From.Nodeid
                        
                        //Decode public key
                        pkdata := header.From.Publickey
                        sha1hash := sha1.New()
                        sha1hash.Write(pkdata)
                        if bytes.Compare(sha1hash.Sum(), desc.Nodeid) != 0 {//If public key or nodeid is wrong
                            self.Answer<-hdr_n_data{nil,nil}
                            return
                        }
                        pk := new(rsa.PublicKey)
                        pk.N = new(big.Int)
                        pk.N.SetBytes(header.From.Publickey.Modulus) 
                        pk.E = *header.From.Publickey.Exponent
                        desc.Publickey = pk
                        
                        if this.Node.AddNode(desc) {
                            this.RecpNode = desc
                            this.NodeAdded = true
                        }
                    }
            
                }
              if header.Encrypted != nil {
                //Decrypt the packet
                //
                //
              }
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

func (this *ConnHandler) Send(data []byte, t, id,part  int32, first,hmac,encrypted bool) {
    //Check if we have publickey
    pk := this.RecpNode.PublicKey
    
    if encrypted {
        if this.RecpNode.PublicKey == nil {
            //Return false, because we need the public key
            return false
        } 
    }
    pdata := this.EncodePacket(data,t,id,part,first,hmac,encrypted) 
    
    
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
    m := NewStore()
    m.Key = key
    m.Value = value
    if len(value) > 3000 {  //Split it up in multiple packets 
    } else {
        mdata,_ := proto.Marshal(m)
        this.Send(mdata,PktType_STORE, msgid, 0,false, true)
        if this.IsAccepted(msgid) {
            return true
        } else {
            return false
        }
    }
}
func (this *ConnHandler) IsAccepted(msgid int) bool {
    header, _ := this.Read(msgid)
    if *header.Type == PktType_ANSWEROK {
        return true
    }
    return false
}
func (this *ConnHandler) WaitPong(msgid int) bool {
    this.Conn.SetReadTimeout(2000000000)
    header,_ := this.Read(msgid)
    if header != nil {return true }
    this.Conn.SetReadTimeout(0)
    return false
}

func NewNode(udpport int) *Node {
    n := new(Node)
    n.Buckets = make(map[int]Bucket)
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
        
        go handler.Start()
    }
}

func (this *Node) GetNodeDesc(key Key) *InNodeDesc {
       
}

func (this *Node) FindCloseNodes(key Key) []*InNodeDesc {
    var found int = 0
    distance := Distance(key, this.Nodeid)
    no := BucketNo(distance)
    ch := this.Buckets[no].Iter()
    for {
        if closed(b) {break;}
        b := <-ch
        
    }
    
    
}

func (this *Node) RemoveNode(key Key) {
    h := NewHot(func(shared map[string]interface{}){
        self := shared["self"].(*GenericHot)
    })
    this.queryHot(h)
    answer:=<-h.Answer
}

func (this *Node) AddNode(node *InNodeDescriptor) bool {
/*

    h := NewHot(func(shared map[string]interface{}){
        self := shared["self"].(*GenericHot)
        */
        distance := XOR(this.Nodeid,node.Nodeid)
        no := BucketNo(distance)

        
        if this.Buckets[no].Len() >= K {
            msgid := NewMsgId()
            this.Buckets[0].Connhandler.Send([...]byte{""}, PktType_PING, msgid, 0, false,false,false)
            if !this.Buckets[0].Connhandler.WaitPong() {
                this.Buckets.PopFront()
                this.Buckets.Push(node)
                return true
            }
            return false
        } 
        this.Buckets[no].Push(node)
        return true
       
/*
    })
    this.queryHot(h)
    answer:=(<-h.Answer).(bool)
    return answer
    */
    return true
}
func (this *InNodeDescriptor) {
    
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
    this.Keypair = keypair
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

