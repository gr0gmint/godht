package dht


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
import "goprotobuf.googlecode.com/hg/proto"
import "fmt"
import "big"

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

type InNodeDescriptor struct { /* In = internal */
    Addr *net.UDPAddr
    Behindnat bool
    Nodeid []byte
    Connhandler *ConnHandler
    Publickey *rsa.PublicKey
    Bucket *Bucket
}


type Bucket struct {
    Node *Node
    v Vector
}
    
func NewBucket(n *Node) *Bucket {
    b := new(Bucket)
    b.Node = n
    return b
}
func (this *Bucket) Len() int {
    return this.v.Len()
}
func (this *Bucket) Less(i,j int) bool {
    distance1 := XOR(this.At(i).Nodeid, this.Node.Nodeid)
    distance2 := XOR(this.At(j).Nodeid, this.Node.Nodeid)
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

func (this *Bucket) Cut(i,j int)  {
    this.v.Cut(i,j)
}
func (this *Bucket) Iter()  chan *InNodeDescriptor {
    ch := this.v.Iter()
    nodech := make(chan *InNodeDescriptor)
    go func(){
        for {
            if closed(ch) { close(nodech); return }
            nodech <- (<-ch).(*InNodeDescriptor)
        }
    }()
    return nodech
}
type Node struct {
    HotRoutine
    Buckets map[int]*Bucket
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
    RecpNode *InNodeDescriptor
    Conn *net.UDPConn
    Buffer []byte
    IdMap map[int32]chan Buf
    Default chan Buf
    FirstPacketSent bool //If the repicient needs the publickey
    NodeIsAdded bool //If the node is added to bucket
}


type Buf []byte
func (b Buf) Write(p []byte) (int, os.Error) {
    copy(b,p)
    return len(p), nil
}
func (b Buf) Read(p []byte) (int, os.Error) {
    copy(p,b)
    return len(b), nil
}


func NewMsgId() int32 {
    return random.Int31()
}

func BucketNo(d Key) uint {
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

func XOR(a, b Key) Key {
	l := len(a)
	if l != len(b) {
		return nil
	}

	d := make(Key, l)

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



type hdr_n_data struct {
    header *Header
    data []byte
}


func (this *ConnHandler) DecodePacket(data Buf) (*Header,[]byte, os.Error) {
    //Read header first
    var hdrlen uint32
    var datalen uint32
    err := binary.Read(data[0:4], binary.BigEndian, &hdrlen)
        if err != nil { return nil,nil,err }
    err = binary.Read(data[4:8], binary.BigEndian, &datalen)
        if err != nil { return nil,nil,err }
    if !(hdrlen < 512 && datalen <= 4096 ) {
        return nil,nil,os.ENOMEM
    }

    header := NewHeader()
    err = proto.Unmarshal(data[8:8+hdrlen], header)
    if err != nil {
        return nil,nil,err
    }
    newdata := make(Buf, datalen)
    copy(newdata,data[8+hdrlen:8+hdrlen+datalen])
    
    
    return header, newdata,nil
}
 
func (this *ConnHandler) EncodePacket(data []byte, t,id,part int32, first,hmac,encrypted bool) []byte {
        newt := NewPktType(t)
        header := NewHeader()
        header.Type = newt
        header.Msgid = proto.Int32(id)
        hdrdata,err := proto.Marshal(header)
        if err != nil {
            fmt.Printf("%s\n", err)
            return nil
        }
        hdrlen := uint32(len(hdrdata))
        datalen :=  uint32(len(data))
        buffer := make(Buf, 8+hdrlen+datalen)
        binary.Write(buffer, binary.BigEndian, [2]uint32{hdrlen,datalen})
        copy(buffer[8:8+len(hdrdata)],hdrdata)
        copy(buffer[8+len(hdrdata):8+len(hdrdata)+len(data)], data) 
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
    this.Default = make(chan Buf)
    go func()  {
        for {
            n, err := this.Conn.Read(this.Buffer)
            if err != nil {continue}
            newbuf := make(Buf, n)
            copy(newbuf, this.Buffer)
            header,_,err := this.DecodePacket(newbuf)
            
            
            if *header.Part >  0 {
                if this.IdMap[*header.Msgid] == nil {
                    this.IdMap[*header.Msgid] = make(chan Buf)
                }
                go func() { this.IdMap[*header.Msgid]<-newbuf}()
            } else {
                go func() { this.Default <- newbuf }()
            }
            
            
        }
    }()
}

func (this *ConnHandler) Read(msgid int32)(*Header, []byte) {
    h := NewHot(func(shared map[string]interface{}){     
        self := shared["self"].(*GenericHot)
        
        if msgid == 0 {
            data := <-this.Default
            header,mdata,err := this.DecodePacket(data)
            if err != nil { self.Answer<-hdr_n_data{nil,nil}} else {
              //If this is some of the first packets received  - needs perhaps to be added to bucket
                if !this.NodeIsAdded {
                    //HMAC and publickey and nodedescriptor objects are mandatory for this first header. If not included, ignore
                    if header.Hmac == nil || header.From == nil || header.From.Publickey == nil {
                        self.Answer<-hdr_n_data{nil,nil}
                        return
                    } else {
                        //Add nodedescriptor to bucket
                       
                        desc := new(InNodeDescriptor)
                        desc.Connhandler = this
                        desc.Addr = this.Conn.RemoteAddr().(*net.UDPAddr)
                        desc.Behindnat = *header.From.Behindnat
                        desc.Nodeid = header.From.Nodeid
                        
                        //Decode public key
                        pkmodulus := header.From.Publickey.Modulus
                        sha1hash := sha1.New()
                        sha1hash.Write(pkmodulus)
                        if bytes.Compare(sha1hash.Sum(), desc.Nodeid) != 0 {//If public key or nodeid is wrong
                            self.Answer<-hdr_n_data{nil,nil}
                            return
                        }
                        pk := new(rsa.PublicKey)
                        pk.N = new(big.Int)
                        pk.N.SetBytes(header.From.Publickey.Modulus) 
                        pk.E = int(*header.From.Publickey.Exponent)
                        desc.Publickey = pk
                        
                        if this.Node.AddNode(desc) {
                            this.RecpNode = desc
                            this.NodeIsAdded = true
                        }
                    }
            
                }
              if header.Isencrypted != nil {
                //Decrypt the packet
                //
                //
              }
              self.Answer<-hdr_n_data{header,mdata}
            }
            return
        } else {
            if this.IdMap[msgid] == nil { this.IdMap[msgid] = make(chan Buf) }
            data :=  <-this.IdMap[msgid]
                        header,mdata,err := this.DecodePacket(data)
            if err != nil { self.Answer<-hdr_n_data{nil,nil}} else {
              self.Answer<-hdr_n_data{header,mdata}
            }
            return
        }   
        
    })
    this.QueryHot(h)
    answer:=(<-h.Answer).(hdr_n_data)
   return answer.header,answer.data
}

func (this *ConnHandler) Send(data []byte, t, id,part  int32, first,hmac,encrypted bool) bool {
    //Check if we have publickey

    
    if encrypted {
        if this.RecpNode.Publickey == nil {
            //Return false, because we need the public key
            return false
        } 
    }
    pdata := this.EncodePacket(data,t,id,part,first,hmac,encrypted) 
    
    
    this.Conn.Write(pdata)   
    return true
}

func (this *ConnHandler) Ping() bool {
    msgid := NewMsgId()
    ping_packet := NewPing()
    ping_data,_ := proto.Marshal(ping_packet)
    this.Send(ping_data, PktType_PING, msgid, 0,false, false,false)
    this.Conn.SetReadTimeout(2000000000)
    header,data := this.Read(msgid)
    this.Conn.SetReadTimeout(0)
    if header == nil || data == nil {
        return false
    }
    if *header.Type == PktType_ANSWERPONG {
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
        this.Send(mdata,PktType_STORE, msgid, 0,false,true,false)
        if this.IsAccepted(msgid) {
            return true
        }
    }
    return false
}
func (this *ConnHandler) IsAccepted(msgid int32) bool {
    header, _ := this.Read(msgid)
    if *header.Type == PktType_ANSWEROK {
        return true
    }
    return false
}

func NewNode(udpport int) *Node {
    n := new(Node)
    n.Buckets = make(map[int]*Bucket)
    return n
}


func NewListener(node *Node, port int) *Listener {
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


func (this *Node) FindCloseNodes(key Key) *Bucket {
    distance := XOR(key, this.Nodeid)

    closenodes := NewBucket(this)
    var ichan chan *InNodeDescriptor
    var first int
    var leap int
    var goleft bool = true
    
    first = int(BucketNo(distance))
    ichan = this.Buckets[first].Iter()
    for closenodes.Len() < K {
        if closed(ichan) {
            if goleft {
                if first - leap <= 0 {
                    goleft = !goleft
                    continue
                }
                ichan = this.Buckets[first - leap].Iter()
                
                if first+leap < 159 {
                    goleft = !goleft
                }
            }
            if !goleft {
                if first + leap >= 159 {
                    goleft = !goleft
                    continue
                }
                ichan = this.Buckets[first + leap].Iter()
                
                if first-leap > 0 {
                    goleft = !goleft
                }
            }
            
        }
        closenodes.Push(<-ichan)

    }
    return closenodes
}

func (this *Node) AddNode(node *InNodeDescriptor) bool {

        distance := XOR(this.Nodeid,node.Nodeid)
        no := int(BucketNo(distance))

        
        if this.Buckets[no].Len() >= K  {
            if !(this.Buckets[no].At(0).Connhandler.Ping()) {
                return false
            }
            return true
        } 
        this.Buckets[no].Push(node)
        return true

}


func (this *Node) Bootstrap(port int, knownhost *net.UDPAddr) bool {
    random.Seed(time.Nanoseconds())

    //Establish private key
    f, err := os.Open("~/.godht/private_key", os.O_RDONLY, 0666) 
    if err != nil {
        os.Mkdir("~/.godht", 0755)
        f,_ = os.Open("~/.godht/private_key", os.O_WRONLY, 0644)
        fmt.Printf("Generating key... \n")
        pk,_ := rsa.GenerateKey(rand.Reader, 2048)
        pkdata := x509.MarshalPKCS1PrivateKey(pk)
        f.Write(pkdata)
        f.Close()
        f,_ = os.Open("~/.godht/private_key", os.O_RDONLY, 0666)
    }
    fi,_ := os.Stat("~/.godht/private_key")
    size := int(fi.Size)
    pkdata := make([]byte, size)
    f.Read(pkdata)

    keypair,_ :=  x509.ParsePKCS1PrivateKey(pkdata)
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
    laddr,_ := net.ResolveUDPAddr("0.0.0.0:5000")
    conn,_ := net.DialUDP("udp", laddr, knownhost)
    c := NewConnHandler(this, conn)
    go c.Start()
    return true
}

