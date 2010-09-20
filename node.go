package dht


import . "container/vector"
import "net"
import "os"
import "crypto/rsa"
import "crypto/x509"
import "crypto/rand"
import "crypto/sha1"
import "crypto/hmac"
import "crypto/aes"
import "crypto/block"
import random "rand"
import "time"
import "encoding/binary"
import "bytes"
import "goprotobuf.googlecode.com/hg/proto"
import "fmt"
import "big"
import "sort"
import "io"

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
    TIMEOUT = 2000000000
    KEYSIZE = 16

)
type Key []byte

type InNodeDescriptor struct { /* In = internal */
    Addr *net.UDPAddr
    Behindnat bool
    Nodeid Key
    Session *UDPSession
    Publickey *rsa.PublicKey
    Bucket *Bucket
    Rendevouz Key
    IsConnected bool
}


type Bucket struct {
    Node *Node
    v *Vector
    sortKey Key
}

type StreamListener struct {
    Ports map[int32](chan *StreamHandler)
}
func NewStreamListener() *StreamListener {
    s := new(StreamListener)
    s.Ports = make(map[int32](chan *StreamHandler))
    return s
}

type StreamHandler struct {
    Session *UDPSession
    Streamid int32
    ReadChan chan *Stream
    AckChan chan *Stream
    Port int32
}
func NewStreamHandler(session *UDPSession, streamid int32, port int32) *StreamHandler {
    s := new(StreamHandler)
    s.Session = session
    s.Streamid = streamid
    s.Port = port
    s.ReadChan = make(chan *Stream)
    s.AckChan = make(chan *Stream)
    go s.Start()
    return s
}

func (this *StreamHandler) Start() {
    var iserr bool
    for {
        iserr =false

        h,d := this.Session.Read(this.Streamid, 0)
                fmt.Printf("In StreamHandler\n")
        if h == nil { iserr = true }
        if *h.Type == PktType_STREAM {
            s := new(Stream)
            err := proto.Unmarshal(d,s)
            if err != nil {
                fmt.Printf("StreamHandler·Start proto.Unmarshal Error: %s\n", err)
                iserr = true
            }
            if iserr {
                s := new(Stream)
                s.Port = proto.Int32(this.Port)
                s.Close = proto.Bool(false)
                s.Ack = proto.Bool(false)
                s.Error = proto.Bool(true)
                ad, _ := proto.Marshal(s)
                this.Session.Send(ad, PktType_STREAM, this.Streamid, true,true)
                continue
            }
            if *s.Ack || *s.Error {
                go func() { this.AckChan <- s } ()
                
            }
            if s.Data != nil {
                go func() {this.ReadChan <- s }()

            }
            if *s.Close {
                this.ReadChan <- nil
                close(this.ReadChan)
                close(this.AckChan)
            }

        }
    }
}

func (this *StreamHandler) Close() {
    s := new(Stream)
    s.Data = nil
    s.Port = proto.Int32(this.Port)
    s.Close = proto.Bool(true)
    s.Ack = proto.Bool(false)
    s.Error = proto.Bool(false)
    sdata,_ := proto.Marshal(s)
    this.Session.Send(sdata, PktType_STREAM, this.Streamid, true,true)
    close(this.ReadChan)
    close(this.AckChan)


}

func (this *StreamHandler) Write(data []byte,encrypted bool) {
    s := new(Stream)
    s.Data = data
    s.Port = proto.Int32(this.Port)
    s.Close = proto.Bool(false)
    s.Ack = proto.Bool(false)
    s.Error = proto.Bool(false)
    sdata,_ := proto.Marshal(s)
    var answer *Stream
    for {
        this.Session.Send(sdata, PktType_STREAM, this.Streamid, true,encrypted)
        answer = <-this.AckChan
        if *answer.Error {
            continue
        } 
        break
    }
    
    
}
func (this *StreamHandler) Read() ([]byte, os.Error) {
    if closed(this.ReadChan) {return nil,nil }
    s := <- this.ReadChan
    if s == nil {
        return nil, os.EOF
    }

    a := new(Stream)
    a.Port = proto.Int32(this.Port)
    a.Close = proto.Bool(*s.Close)
    a.Ack = proto.Bool(true)
    a.Error = proto.Bool(false)
    ad,_ := proto.Marshal(a)
    this.Session.Send(ad, PktType_STREAM, this.Streamid, true,true)
    return s.Data, nil
    
}


type Atom struct {
    HotRoutine
    Died bool
}
func NewAtom() *Atom {
    a := new(Atom)
    a.Died = false
    go a.HotStart()
    return a
}
func (this *Atom) Do(joe func() ) {
    if this.Died { return }
    h := NewHot(func(shared map[string]interface{}){
        self := shared["self"].(*GenericHot)
        joe()
        self.Answer<-true
    })
    this.QueryHot(h)
    <-h.Answer
}
func (this *Atom) Kill () {
    this.Died = true
}



func NewBucket(n *Node) *Bucket {
    b := new(Bucket)
    b.Node = n
    b.v = new(Vector)
    return b
}
func (this *Bucket) SetSortKey(key Key) {
    this.sortKey = key
}

func (this *Bucket) Len() int {
    return this.v.Len()
}
func (this *Bucket) Less(i,j int) bool {
    if this.sortKey == nil {
        distance1 := XOR(this.At(i).Nodeid, this.Node.Nodeid)
        distance2 := XOR(this.At(j).Nodeid, this.Node.Nodeid)
        return distance1.Less(distance2)
    } 
    distance1 := XOR(this.At(i).Nodeid, this.sortKey)
    distance2 := XOR(this.At(j).Nodeid, this.sortKey)
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




type Node struct {
    HotRoutine
    Buckets map[int]*Bucket
    Nodeid Key
    Reachable bool
    Keypair *rsa.PrivateKey
    Listenport int
    Handler *UDPHandler
    TotalNodes int
    Data Datastore
    StreamListener *StreamListener
}

type Listener struct {
    Node *Node
    Port int
}

type UDPHandler struct {
    Buffer Buf
    Node *Node
    HotRoutine
    Conn *net.UDPConn
    FromMap map[string]chan Buf
    SessionChan chan *UDPSession
}
func NewUDPHandler(port int, node *Node) *UDPHandler {
    
    u := new(UDPHandler)
    laddr,_ := net.ResolveUDPAddr(fmt.Sprintf("0.0.0.0:%d",port))
    u.Conn,_ = net.ListenUDP("udp",laddr) 
    u.FromMap = make(map[string]chan Buf)
    u.SessionChan = make(chan *UDPSession)
    u.Node = node
    return u
}

type UDPSession struct {
    Atom *Atom
    Handler *UDPHandler
    RAddr *net.UDPAddr
    HotRoutine
    Node *Node
    RecpNode *InNodeDescriptor
    IdMap map[int32]chan hdr_n_data
    PartMapIn map[int32]int32
    PartMapOut map[int32]int32
    Default chan hdr_n_data
    NeedToSendDesc bool //If the repicient needs the publickey
    NodeIsAdded bool //If the node is added to bucket
    First bool //Keep track of the first packet sent
    NeedToSendKey bool
    EncryptKey []byte
    DecryptKey []byte
    FirstMap map[int32]bool
    
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

func ReadAll (r io.Reader, b []byte)  {
    l := len(b)
    total := 0
    var n int
    for {
        if l-total < KEYSIZE {
            return
        } else {
            n, _ = r.Read(b[total:total+KEYSIZE])
        }
        total += n
        if n == 0 { break }

    }
}
func WriteAll (w io.Writer, b []byte) {
    l := len(b)
    total := 0
    var n int
    for {
        if l-total < KEYSIZE  {
            joe := [16]byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
            nb := bytes.NewBuffer(b[total:])
            nb.Write(joe[0:16-(l-total)])
            w.Write(nb.Bytes())
            break
        } else {
            n, _ = w.Write(b[total:total+KEYSIZE])
        }
        if n == 0 { break }
        total += n
    }
}


func NewId() int32 {
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


func (this *UDPSession) DecodePacket(data Buf) (*Header,[]byte, os.Error) {
    //Read header first
    var chdrlen uint32
    var hdrlen uint32
    var datalen uint32
    if len(data) < 8 {
        fmt.Printf("len(data) < 8\n")
        return nil,data,os.ENOMEM
    }
    err := binary.Read(data[0:4], binary.BigEndian, &chdrlen)
        if err != nil { return nil,nil,err }
    payload := data[4+chdrlen:]
    fmt.Printf("Length of payload = %d\n", len(payload))
        


    fmt.Printf("chdrlen = %d, len(payload) = %d\n", chdrlen, len(payload))
    cryptoheader := new(CryptoHeader)
    err = proto.Unmarshal(data[4:4+chdrlen], cryptoheader)
    if err != nil {
        fmt.Printf("Returning error\n")
        return nil,data,err
    }
    if *cryptoheader.Needkey {
        fmt.Printf("Recipient needs key\n")
        this.NeedToSendKey = true
    }
    //VERIFY AND/OR DECRYPT
    if cryptoheader.Key != nil {
        h := sha1.New()
        this.DecryptKey, err = rsa.DecryptOAEP(h,rand.Reader, this.Node.Keypair, cryptoheader.Key, [...]byte("GONUTS")[:]) 
        fmt.Printf("DecryptKey = %x\n", this.DecryptKey)
    }
    
    if *cryptoheader.Isencrypted && this.DecryptKey == nil {
        return nil,nil,os.NewError("Has no decryptionkey")
    }
    if  cryptoheader.Hmac != nil && this.DecryptKey != nil {
        hm := hmac.NewSHA1(this.DecryptKey)
        hm.Write(payload)
        sum := hm.Sum()
        fmt.Printf("HMAC? %x =?= %x\n", cryptoheader.Hmac, sum)
        if bytes.Compare(cryptoheader.Hmac, sum) == 0 {
            fmt.Printf("HMAC verified\n")
            
        } else {
            return nil,nil,os.NewError("HMAC didn't verify\n")
        }
    }
    if *cryptoheader.Isencrypted {
        fmt.Printf("Packet is encrypted! Decrypting!\n")
        cipher,_ := aes.NewCipher(this.DecryptKey)
        ciphertext := bytes.NewBuffer(payload)
        cbc := block.NewCBCDecrypter(cipher, this.DecryptKey, ciphertext)
        fmt.Printf("%x\n", this.DecryptKey)
        ReadAll(cbc,payload)
    }

    err = binary.Read(payload[0:4], binary.BigEndian, &hdrlen)
        if err != nil { return nil,data,err }
    err = binary.Read(payload[4:8], binary.BigEndian, &datalen)
        if err != nil { return nil,data,err }
    fmt.Printf("hdrlen = %d, datalen = %d, len(payload) = %d\n", hdrlen, datalen,len(payload))
    if !(hdrlen < 2048 && datalen <= 8096 ) {
        fmt.Printf("Packet too big!\n")
        return nil,data,os.ENOMEM
    }
    hdrdata := payload[8:8+hdrlen]
    newdata := payload[8+hdrlen:8+hdrlen+datalen]
    header := new(Header)
    
    err = proto.Unmarshal(hdrdata, header)
    if err != nil {
        return nil,nil,err
    }
    //Verify timestamp
    difference := *header.Timestamp - time.Seconds()
    if difference < -(5*60) || difference > (5*60) {
        return nil,nil,os.NewError("Timestamp is too far off\n")
    }
    
    if _,ok := this.PartMapIn[*header.Streamid]; !ok {
        this.PartMapIn[*header.Streamid] = 0        
    }
    
    if *header.Part != this.PartMapIn[*header.Streamid] {
        fmt.Printf("%d != %d\n", *header.Part, this.PartMapIn[*header.Streamid])
        return nil,nil, os.NewError("Unexpected Part-number (Packet number)")
    } 
    
    this.PartMapIn[*header.Streamid]++
    this.FirstMap[*header.Streamid] = true
    newdata2 := make(Buf, datalen)
    copy(newdata2,newdata)
    
    return header, newdata2,nil
}
 
func (this *UDPSession) EncodePacket(data []byte, t,id int32, ishmac,encrypted bool) []byte {
        newt := NewPktType(t)
        header := new(Header)
        header.Type = newt
        header.Streamid = proto.Int32(id)
        if _,ok := this.FirstMap[id]; !ok {
            header.Syn = proto.Bool(true) 
            fmt.Printf("Syn = true\n")
        } else {
            header.Syn = proto.Bool(false)
        }
        this.FirstMap[id] = true
        header.Part = proto.Int32(this.PartMapOut[id])
        fmt.Printf("header.Part = %d\n", *header.Part)
        header.Timestamp = proto.Int64(time.Seconds())
        fmt.Printf("NodeIsAdded = %t\n", this.NodeIsAdded)
        header.Knowsyou = proto.Bool(this.NodeIsAdded)

    
        this.PartMapOut[*header.Streamid]++
        
        if this.NeedToSendDesc {
            //Include publickey
            fmt.Printf("NeedToSendDesc is set!\n")
            header.From = this.Node.Descriptor()

        }
        if this.RecpNode == nil {
            encrypted = false
        }
        hdrdata,err := proto.Marshal(header)
        if err != nil {
            fmt.Printf("%s\n", err)
            return nil
        }
        
        hdrlen := uint32(len(hdrdata))
        datalen :=  uint32(len(data))
        
        p := bytes.NewBufferString("")
        binary.Write(p, binary.BigEndian, [2]uint32{hdrlen,datalen})
        p.Write(hdrdata)
        p.Write(data)
        payload := p.Bytes()
        fmt.Printf("len(payload) before crypto = %d\n", len(payload))
        
        cryptoheader := new(CryptoHeader)
        cryptoheader.Isencrypted = proto.Bool(encrypted)
        if this.DecryptKey == nil {
            cryptoheader.Needkey = proto.Bool(true)
        } else {
            cryptoheader.Needkey = proto.Bool(false)
         }
        if this.RecpNode != nil {
            if this.EncryptKey == nil {
                this.EncryptKey = make([]byte, KEYSIZE)
                rand.Reader.Read(this.EncryptKey)
                fmt.Printf("EncryptKey = %x\n", this.EncryptKey)
            }
            
            if this.NeedToSendKey { //Recipient hasn't got EncryptKey yet
                h := sha1.New()
                fmt.Printf("Encrypting key!\n")
                cryptoheader.Key, err = rsa.EncryptOAEP(h, rand.Reader, this.RecpNode.Publickey, this.EncryptKey, [...]byte("GONUTS")[:])
                this.NeedToSendKey = false
            }
            
            if encrypted {
                fmt.Printf("Ciphertext with key: %x\n", this.EncryptKey)
                cipher,_ := aes.NewCipher(this.EncryptKey)
                ciphertext := bytes.NewBufferString("")
                cbc := block.NewCBCEncrypter(cipher, this.EncryptKey, ciphertext)
                WriteAll(cbc,payload)
                payload = ciphertext.Bytes()
            }
            if ishmac {

                hm := hmac.NewSHA1(this.EncryptKey)
                hm.Write(payload)
                cryptoheader.Hmac = hm.Sum()

                                fmt.Printf("HMAC'ing: %x\n", cryptoheader.Hmac)
            }

        }
        fmt.Printf("len(payload) after crypto = %d\n", len(payload))
        chdrdata,err := proto.Marshal(cryptoheader)
        
        if err != nil {
            fmt.Printf("%s\n", err)
            return nil
        }   
        
        
        
        chdrlen := uint32(len(chdrdata))
        fmt.Printf("Sending with: chdrlen = %d, hdrlen = %d, datalen = %d\n", chdrlen, hdrlen, datalen)
        buffer := make(Buf, 4+chdrlen+uint32(len(payload)))
        binary.Write(buffer, binary.BigEndian, [1]uint32{chdrlen})

        copy(buffer[4:],chdrdata)
        copy(buffer[4+chdrlen:], payload)
        return buffer
}



func NewUDPSession(raddr *net.UDPAddr, node *Node, udphandler *UDPHandler) *UDPSession {
    c := new(UDPSession)
    c.RAddr =  raddr
    c.Handler = udphandler
    c.Node = node
    c.First = true
    c.NeedToSendKey = true
    c.Atom = NewAtom()
    c.Handler.FromMap[raddr.String()] = make(chan Buf)
    c.FirstMap = make(map[int32]bool)
    /*
    if c.Handler.FromMap[raddr.String()] == nil {
        c.Handler.FromMap[raddr.String()] = make(chan Buf)
    }
    */
    c.PartMapIn = make(map[int32]int32)
    c.PartMapOut = make(map[int32]int32)
    c.IdMap = make(map[int32]chan hdr_n_data)
    go c.HotStart()
    
    return c
}

func (this *UDPHandler) Start() {
    go this.HotStart()
    fmt.Printf("UDPHandler started\n")
    this.Buffer = make(Buf, 10000)
    this.SessionChan = make(chan *UDPSession)
        go func() { for {
            n, addr, err := this.Conn.ReadFromUDP(this.Buffer)
            saddr := addr.String()
            if err != nil {fmt.Printf("%s", err); break}
            newbuf := make(Buf, n)
            copy(newbuf, this.Buffer)
            fmt.Printf("Checking if FromMap[%s] is nil\n", saddr)
            if d,ok :=  this.FromMap[saddr]; !ok || d == nil {
                fmt.Printf("Creating new UDP session\n")
                session := NewUDPSession(addr, this.Node, this)
                go session.Start()
               go func() {this.SessionChan <- session} ()
            }  
               fmt.Printf("Piping newbuf\n")
                go func() { this.FromMap[saddr]<-newbuf}()
            
        }
        }()
    
}

func (this *UDPHandler) GetSession() *UDPSession {
    s := <-this.SessionChan
    return s 
}

func (this *UDPSession) _handleStore(header *Header, data []byte) {
    v := bytes.NewBufferString("")
    p := new(Store)

    fmt.Printf("_handleStore\n")
    for {
        err := proto.Unmarshal(data,p)
        
        if err != nil { 
            fmt.Printf("err: %s\n", err)
            answer := new(AnswerOk)
            answer.Ok = proto.Bool(false)
            adata,_ := proto.Marshal(answer)
            this.Send(adata, PktType_ANSWEROK, *header.Streamid, true,false)
            break
        }
        v.Write(p.Value)
        answer := new(AnswerOk)
        answer.Ok = proto.Bool(true)
        adata,_ := proto.Marshal(answer)
        this.Send(adata, PktType_ANSWEROK, *header.Streamid, true,false)
        

        if *p.Ismore {
            header,data = this.Read(*header.Streamid, 0)
        } else {
            fmt.Printf("Setting a value\n")
            this.Node.Data.Set(p.Key, v)
            answer := new(AnswerOk)
            answer.Ok = proto.Bool(true)
            adata,_ := proto.Marshal(answer)
            this.Send(adata, PktType_ANSWEROK, *header.Streamid, false,false)
            break
        }
    }
      
}

func (this *UDPSession) Start() {
    fmt.Printf("UDPSession started\n")
    this.Default = make(chan hdr_n_data)
    saddr := this.RAddr.String()
    packetchan := this.Handler.FromMap[saddr]
    go func() {
        for {
            packet := <-packetchan
            if packet == nil {fmt.Printf("Error reading from UDPHandler"); break }
            header,data,err := this.DecodePacket(packet)
            if err != nil {
                fmt.Printf("Start·E: %s\n", err)
                continue
            }
            if header == nil {
                fmt.Printf("Header isn't valid\n")
                continue
            }


            if !(*header.Syn) {
                if d, ok := this.IdMap[*header.Streamid]; !ok || d == nil {
                    this.IdMap[*header.Streamid] = make(chan hdr_n_data)
                }
                go func() { fmt.Printf("this.IdMap[%d]<-packet\n", *header.Streamid); this.IdMap[*header.Streamid]<-hdr_n_data{header,data}}()
            } else {
                fmt.Printf("Piping into this.Default\n")
                go func() { this.Default <- hdr_n_data{header,data} }()
            }
            
            
        }
    } ()
    
    
    //(data []byte, t, id,part  int32, first,hmac,encrypted bool) bool 
    go func() { for {
        header, data := this.Read(0, 0)
        
        if header == nil { fmt.Printf("Header is nil :(\n"); continue }
                                fmt.Printf("The packet is of type %s, streamid = %d\n", PktType_name[int32(*header.Type)], *header.Streamid)
        switch *header.Type {
            case PktType_STORE:
                go this._handleStore(header,data)
            case PktType_FINDNODE:
                p := new(FindNode)
                err := proto.Unmarshal(data,p)
                if err != nil {
                    fmt.Printf("E: %s\n", err)
                    break
                }
                nodeid := p.Key
                close := this.Node.FindCloseNodes(nodeid)
                descriptors := make([]*NodeDescriptor, close.Len())
                l:=close.Len()
                fmt.Printf("There are %d close nodes\n", l)
                for  i:=0; i < l; i++ {
                    fmt.Printf("%x\n", keytobyte(close.At(i).Nodeid))
                    descriptors[i] = close.At(i).ToNodeDescriptor()
                }
                answer := new(AnswerFindNode)
                answer.Nodes = descriptors
                if *p.Findvalue {
                    answer.Value = this.Node.Data.Get(p.Key)
                    fmt.Printf("Sending back this value: %s\n", answer.Value)
                }
                adata,err := proto.Marshal(answer)
                if err != nil { fmt.Printf("E: %s\n", err) }
                this.Send(adata, PktType_ANSWERNODES, *header.Streamid,true,true)
            case PktType_PING:
                a := new(Pong)
                adata,err := proto.Marshal(a)
                if err != nil  {fmt.Printf("E: %s\n", err)}
                this.Send(adata, PktType_ANSWERPONG,*header.Streamid, true,false)
                
            case PktType_STREAM:
                s := new(Stream)
                err := proto.Unmarshal(data, s)
                
                if err == nil {
                    go this._handleStream(header,s)
                } else {
                    fmt.Printf("PktType_STREAM:ERR: %s\n", err)
                }
        }
    }
    }()
    
}

func (this *UDPSession) _handleStream(header *Header, s *Stream) {
    fmt.Printf("_handleStream\n")
    port := *s.Port
    handler := NewStreamHandler(this, *header.Streamid, port)
    //go handler.Start()
    go func() { handler.ReadChan <- s }()
    if !this.Node.StreamListener.AddStream(port,handler) {
        return
    }
    
}


func (this *StreamListener) AddStream(port int32, handler *StreamHandler) bool {
    if _, ok := this.Ports[port]; !ok {
        this.Ports[port] = make(chan *StreamHandler)
    }
    this.Ports[port] <- handler
    return true
}

func DecodePublicKey(p *Publickey) *rsa.PublicKey {
    pk := new(rsa.PublicKey)
    pk.N = new(big.Int)
    pk.N.SetBytes(p.Modulus) 
    pk.E = int(*p.Exponent)
    return pk                      
}

func EncodePublicKey(p *rsa.PublicKey) *Publickey {
    pk := new(Publickey)
    pk.Modulus = p.N.Bytes() 
    pk.Exponent = proto.Int32(int32(p.E))
    return pk                      
}


func (this *Node) Descriptor() *NodeDescriptor {


    n := new(NodeDescriptor)
        n.Udpport = proto.Int32(int32(this.Listenport))
    n.Nodeid = this.Nodeid
    n.Behindnat = proto.Bool(this.Reachable)
    n.Publickey = EncodePublicKey(&this.Keypair.PublicKey)
    return n
}

func (this *UDPSession) AddRecpNode(from *NodeDescriptor) {
                    //HMAC and publickey and nodedescriptor objects are mandatory for this first header. If not included, ignore
                    
                        //Add nodedescriptor to bucket
                        fmt.Printf("Adding node to bucket\n")
                        desc := new(InNodeDescriptor)
                        desc.Session = this
                        desc.Addr = this.RAddr
                        desc.Behindnat = *from.Behindnat
                        desc.Nodeid = from.Nodeid
                        desc.IsConnected = true
                        
                        //Verify
                        pkmodulus := from.Publickey.Modulus
                        sha1hash := sha1.New()
                        sha1hash.Write(pkmodulus)
                        if bytes.Compare(sha1hash.Sum(), desc.Nodeid) != 0 {//If public key or nodeid is wrong
                            fmt.Printf("Verification failed\nSHA1 = %x\nNodeid = %x\n", sha1hash.Sum(), desc.Nodeid)
                            //self.Answer<-hdr_n_data{nil,nil}
                            //return
                            return
                        } else {
                            fmt.Printf("Verification succeded!!\nSHA1 = %x\nNodeid = %x\n", sha1hash.Sum(), keytobyte(desc.Nodeid))
                        }
                        pk := DecodePublicKey(from.Publickey)
                        desc.Publickey = pk
                        this.Node.AddNode(desc)
                        this.RecpNode = desc
                        this.NodeIsAdded = true
                    
            
}

func (this *UDPSession) Read(streamid int32, timeout int64)(*Header, []byte) {
    /*h := NewHot(func(shared map[string]interface{}){    
        defer func() {fmt.Printf("returning from read hot\n")}()
        
        self := shared["self"].(*GenericHot)
        */
        fmt.Printf("Reading %d, with timeout=%d\n", streamid, timeout)
        var data hdr_n_data
        var ticker *time.Ticker
        if timeout != 0  {
            ticker = time.NewTicker(timeout)
        }
        
        if streamid == 0 {
            if timeout != 0 {
            select {
                case data = <-this.Default:
                    break
                case <-ticker.C:
                    ticker.Stop()
                    fmt.Printf("Ticker problem. Timeout = %d\n", timeout)
                    //self.Answer<-hdr_n_data{nil,nil}
                    return nil,nil
                   
            }
            } else {
                data = <-this.Default
            }
  
        } else {
   
            if d,ok := this.IdMap[streamid]; !ok || d == nil { fmt.Printf("make(chan Buf)\n"); this.IdMap[streamid] = make(chan hdr_n_data) }

            fmt.Printf("GONNA DO DIS\n")
            if timeout == 0 {
                data =  <-this.IdMap[streamid]
                fmt.Printf("After nt\n")
                
            }  else {
                select {
                    case data =  <-this.IdMap[streamid]:
                        break
                    case <-ticker.C:
                        ticker.Stop()
                        //self.Answer<-hdr_n_data{nil,nil}
                        
                        return nil,nil 
                }
                fmt.Printf("After wt\n")
            }
        }
          if this.RecpNode != nil {
            this.Node.MoveKeyToTop(this.RecpNode.Nodeid) //There is activity, so we move the nodeid to the top of the bucket
            }
            header := data.header
            mdata := data.data
            if header == nil {
                return nil,nil
            }
            //Set the NeedToSendDesc flag, if "Knowsyou" is set in packet
            fmt.Printf("header Knowsyou = %t\n", *header.Knowsyou)
            if *header.Knowsyou {fmt.Printf("Setting NeedToSendDesc\n"); this.NeedToSendDesc = false } else { this.NeedToSendDesc = true }
              //If this is some of the first packets received  - needs perhaps to be added to bucket
              if !this.NodeIsAdded { this.AddRecpNode(header.From) }
              
              return header,mdata
        /*
    })
    this.QueryHot(h)
    *//*
    answer:=(<-h.Answer).(hdr_n_data)
   return answer.header,answer.data
   */
   
}

func (this *UDPSession) Send(data []byte, t, id  int32,hmac,encrypted bool) bool {
    //Check if we have publickey

    
    if encrypted {
        if this.RecpNode.Publickey == nil {
            //Return false, because we need the public key
            return false
        } 
    }
        if this.NeedToSendDesc {    fmt.Printf("NeedToSendDesc flag is set\n") }
    pdata := this.EncodePacket(data,t,id,hmac,encrypted)
    fmt.Printf("Sending with streamid: %d to %s\n", id, this.RAddr)

    this.Handler.Conn.WriteTo(pdata,this.RAddr)
    if this.RecpNode != nil { 
    this.Node.MoveKeyToTop(this.RecpNode.Nodeid)  
    }
    return true
}

func (this *UDPSession) Ping() bool { 
    streamid := NewId()
    ping_packet := new(Ping)
    ping_data,_ := proto.Marshal(ping_packet)
    this.Send(ping_data, PktType_PING, streamid,  true,false)
    header,data := this.Read(streamid,2000000000)
    if header == nil || data == nil {
        return false
    }
    if *header.Type == PktType_ANSWERPONG {
        return true
    }
    return false
}

//REturns the unmarshalled protobuf packet
func (this *UDPSession) _findNode(key Key, findvalue bool) *AnswerFindNode{
    streamid := NewId()
    m := new(FindNode)
    m.Key = key
    m.Findvalue = proto.Bool(findvalue)
    data, err := proto.Marshal(m)
    if err != nil {
        fmt.Printf("E: %s\n", err)
    }
    fmt.Printf("Sending FINDNODE packet with streamid = %d\n", streamid)
    this.Send(data, PktType_FINDNODE, streamid,  true,false)
    header,data := this.Read(streamid,TIMEOUT)
    if header == nil {
        return nil
    }
    fmt.Printf("Answer is of type: %s\n\n", PktType_name[int32(*header.Type)])
    if *header.Type == PktType_ANSWERNODES {
        fmt.Printf("Got an answer!\n")
        answer := new(AnswerFindNode)
        err := proto.Unmarshal(data,answer)
        if err != nil {
            fmt.Printf("ERROR: %s\n", err)
        }
        return answer 
    } 
    return nil
}


func (this *NodeDescriptor) ToInNodeDescriptor() *InNodeDescriptor {
    innode := new(InNodeDescriptor)
    innode.Behindnat = *this.Behindnat
    innode.Nodeid = make(Key, B/8)
    copy(innode.Nodeid, this.Nodeid)
    if this.Publickey != nil {
        innode.Publickey = DecodePublicKey(this.Publickey)
    }
    innode.Addr = new(net.UDPAddr)
    innode.Addr.Port = int(*this.Udpport)
    innode.Rendevouz = this.Rendevouz
    if this.Ipaddr != nil {
        innode.Addr.IP = this.Ipaddr
    }
    innode.IsConnected = false
    return innode
}

func (this *InNodeDescriptor) ToNodeDescriptor() *NodeDescriptor {
    node := new(NodeDescriptor)
    node.Behindnat = proto.Bool(this.Behindnat)
    node.Nodeid = make(Key, B/8)
    copy(node.Nodeid, this.Nodeid)
    if this.Publickey != nil {
        node.Publickey = EncodePublicKey(this.Publickey)
    }
    node.Udpport = proto.Int(this.Addr.Port)
    node.Ipaddr = this.Addr.IP
    node.Rendevouz = this.Rendevouz
    fmt.Printf("node.Ipaddr = %x\n", node.Ipaddr)
    return node        
}
    
func (this *UDPSession) FindNode(key Key) *Bucket {

    answer := this._findNode(key, false)
    fmt.Printf("Got the answer: %s\n", answer)
    nodes := NewBucket(this.Node)
    if answer != nil {
        if len(answer.Nodes) == 0 { return nil }
        fmt.Printf("Trying to add the nodes\n")
        for _,v := range answer.Nodes {
            fmt.Printf("A: %x\n", v.Nodeid)
            innode := v.ToInNodeDescriptor()
            this.Node.AddNode(innode)
            nodes.Push(innode)
        }
    } else { return nil }
    return nodes
}
func (this *UDPSession) FindValue(key Key) (*Bucket, []byte) {
    answer := this._findNode(key, true)
    fmt.Printf("Got the answer: %s\n", answer)
    nodes := NewBucket(this.Node)
    if answer != nil {
        fmt.Printf("ANSWER IS NOT NIL\n")
        if answer.Value != nil {
            return nil,answer.Value
        }
        fmt.Printf("Trying to add the nodes\n")
        for _,v := range answer.Nodes {
            innode := v.ToInNodeDescriptor()
            nodes.Push(innode)
            this.Node.AddNode(innode)
        }
    }
    return nodes,nil
}

func (this *UDPSession) Store(key Key, value io.Reader) bool {
    streamid := NewId()
    b := make([]byte, 3000)
    for {
        fmt.Printf("Reading\n")
        n,err := value.Read(b)
        fmt.Printf("n = %d\n", n)
        if n != 0 {
            m := new(Store)
            m.Key = key
            m.Value = b[0:n]
            if err != nil { m.Ismore = proto.Bool(false) } else { m.Ismore = proto.Bool(false) }
            mdata,_ := proto.Marshal(m)
            this.Send(mdata,PktType_STORE, streamid, true,false)
            if !this.IsAccepted(streamid) {
                return false
            }
        } else {
            break
        }
        if err != nil {
        break
        }
    }
    fmt.Printf("I sent the store command\n")
    return true
}
func (this *UDPSession) IsAccepted(streamid int32) bool {
    header, _ := this.Read(streamid,0)
    if *header.Type == PktType_ANSWEROK {
        return true
    }
    return false
}

func NewNode() *Node {
    n := new(Node)
    n.Buckets = make(map[int]*Bucket)
    n.Data = NewSimpleDatastore()
    n.StreamListener = NewStreamListener()
    go n.HotStart()
    return n
}



func (this *Node) FindCloseNodes(key Key) *Bucket {
    distance := XOR(key, this.Nodeid)

    closenodes := NewBucket(this)
    var first int
    var leap int = 0
    var goright bool = true
    first = int(BucketNo(distance))
    if this.Buckets[first] == nil {
        this.Buckets[first] = NewBucket(this)
    }

    i := 0
    var len int
    for closenodes.Len() < K {
        if (first + leap) > 159 &&  ( first - leap) < 0 {
           break
        }
        if goright {
        if this.Buckets[first+leap] == nil { len = 0 } else { len = this.Buckets[first+leap].Len() }
        } else {
        if this.Buckets[first-leap] == nil { len = 0 } else {  len = this.Buckets[first-leap].Len() }
        }
        if i >= len {
            leap ++
            i = 0
            goright = !goright
        } else {
        if goright {
            if  this.Buckets[first+leap].At(i) != nil {
                closenodes.Push(this.Buckets[first+leap].At(i))
            }
        } else {
            if this.Buckets[first-leap].At(i) != nil {
                closenodes.Push(this.Buckets[first-leap].At(i))
            }
        }
        i++
        }
    }
    
    return closenodes
}
func (this *Node) HasNode(key Key) (bool, *InNodeDescriptor) {
    distance := XOR(this.Nodeid,key)
    no := int(BucketNo(distance))
    len := this.Buckets[no].Len()
    for i := 0; i <len; i++{
        if this.Buckets[no].At(i) == nil {break }
        if bytes.Compare(this.Buckets[no].At(i).Nodeid, key) == 0 { return true, this.Buckets[no].At(i)}
    }
    return false, nil
    
}
func (this *Node) AddNode(node *InNodeDescriptor) bool  {
    h := NewHot(func(shared map[string]interface{}){
        self := shared["self"].(*GenericHot)
        distance := XOR(this.Nodeid,node.Nodeid)
        no := int(BucketNo(distance))
        
        
        if this.Buckets[no] == nil {
            this.Buckets[no] = NewBucket(this)
        }
        if ok,n := this.HasNode(node.Nodeid); ok {
            fmt.Printf("Already have this node: %x\n", keytobyte(node.Nodeid))
            
            //HACK
            node.Session= n.Session
            node.Addr = n.Addr
            
            
            self.Answer <- false
            return
        }
        if bytes.Compare(node.Nodeid, this.Nodeid) == 0 {
            fmt.Printf("This is myself: %x\n", keytobyte(node.Nodeid))
            self.Answer <- false
            return 
        }
        fmt.Printf("Adding %x - %s\n",  keytobyte(node.Nodeid), node.Addr)
        this.TotalNodes++
        fmt.Printf("\n\nTotal node count = %d\n\n", this.TotalNodes)
        if node.Session == nil {
            node.Session = NewUDPSession(node.Addr,this,this.Handler)
            node.Session.NodeIsAdded = true
            node.Session.NeedToSendDesc= true
            go node.Session.Start()
        }
        if this.Buckets[no].Len() >= K  {
            fmt.Printf("BUCKET IS FULL - TRYING TO PING\n")
            fmt.Printf("this.Buckets[no].At(0).Session.RAddr =%s\n", this.Buckets[no].At(0).Session.RAddr)
            go func() {
                if !(this.Buckets[no].At(0).Session.Ping()) {
                    this.Buckets[no].Cut(0,1)
                     this.Buckets[no].Push(node)
                     self.Answer<-true
                } else {
                     self.Answer<-false 
                }
            }()
        } else {
                 this.Buckets[no].Push(node)
                         self.Answer<-true
        }
        


 
    })
    this.QueryHot(h)
    answer:=(<-h.Answer).(bool)
    return answer
}

func (this *Node) StreamConnect(nodeid Key, port int32) *StreamHandler {
    if bytes.Compare(nodeid, this.Nodeid) == 0 {
        fmt.Printf("This is me\n")
        return nil
    }
    closenodes := this.FindCloseNodes(nodeid)
    if closenodes.Len() == 0 || bytes.Compare(closenodes.At(0).Nodeid, nodeid) != 0 {
        closenodes = this.IterativeFindNode(nodeid)
    }
    if closenodes.Len() ==0 || bytes.Compare(closenodes.At(0).Nodeid, nodeid) != 0 {
        return nil
    }
    return NewStreamHandler(closenodes.At(0).Session, NewId(), port)
}


func (this *Node) IterativeFindNode(key Key) *Bucket {
    fmt.Printf("IterativeFindNode\n")
    hasnodes := this.FindCloseNodes(key)
    
    cancel := new(bool)
    *cancel = false
    
    ch := make(chan bool)
    done := make (chan bool)

    async := NewAtom()
    var shortlist *Bucket
    nodelist := NewBucket(this)
    closest := make(Key, 20)
    alreadyAsked := NewBucket(this)
    shortlist=hasnodes
    fmt.Printf("Length of shortlist = %d\n", shortlist.Len())
     at := 0
     
    for {

    go func() {
        for i:= at; i < shortlist.Len()  && i < at+Alpha; i++ {

                ic := i
                go func() {
                    defer func() {ch <- false; at++}()
                    fmt.Printf("hasnodes.At(%d)\n", ic)
                    inode :=  shortlist.At(ic)
                    if inode != nil {
                        already := false
                        jlen := alreadyAsked.Len()
                        async.Do(func() {
                            for  j:= 0; j<jlen; j++ {

                                
                                if bytes.Compare(alreadyAsked.At(j).Nodeid, inode.Nodeid) == 0 {already=true; break}
                            }
                           if !already {
                                alreadyAsked.Push(inode)
                            }
                            
                                donotadd := false
                                    if bytes.Compare(inode.Nodeid, this.Nodeid) == 0 { donotadd = true }
                                    if !donotadd {
                                        nodelist.Push(inode)
                                }
                            
                        })
                        if !already {
                            fmt.Printf("Asking peer %x\n", keytobyte(inode.Nodeid))
                            nodes := inode.Session.FindNode(key)
                                                        fmt.Printf("Done Asking\n")
                            closer := false
                            if nodes == nil {return }
                             len :=  nodes.Len()
                            async.Do(func() { 

                                for j:= 0; j<len; j++ {
                                    n := nodes.At(j)
                                    donotadd := false
                                    if bytes.Compare(n.Nodeid, this.Nodeid) == 0 { donotadd = true }
                                    for k := 0; k < nodelist.Len(); k++ {
                                        if bytes.Compare(n.Nodeid, nodelist.At(k).Nodeid) == 0   { donotadd = true; }
                                    }
                                    if !donotadd {
                                        nodelist.Push(n)
                                    }
                                    if XOR(n.Nodeid, key).Less( XOR(closest, key) )  {
                                        closer =true
                                    }
                                }
                                if closer {
                                    ch <- true
                                } else {
                                    ch <- false
                                }
                            })
                            fmt.Printf("Back from async\n")
                          
                        }

                    }
                }()
        }
        closer := false
        for i:= 0; i < shortlist.Len()  && i < Alpha; i++ {
            fmt.Printf("i = %d\n", i)
            a := <-ch
            if a {closer = true; async.Kill(); async = NewAtom(); break}
        }
        fmt.Printf("done <-closer\n")
        done <-closer
      }()
    fmt.Printf("waiting\n")
    a := <-done
    fmt.Printf("done waiting\n")
    if a { 
        nodelist.SetSortKey(key)
        sort.Sort(nodelist)
        shortlist := NewBucket(this)
        for i := 0; i < 20 && i < nodelist.Len(); i++ {

        shortlist.Push(nodelist.At(i))

        }
        at = 0
        continue
    } else if at+Alpha > shortlist.Len() {
        fmt.Printf("at+Alpha > shortlist.Len()\n")
        break
    } else {
       at += Alpha
       fmt.Print("Continuing ... shortlist.Len() = %d\n", shortlist.Len())
       continue
    }
    }
    l := nodelist.Len()
        nodelist.SetSortKey(key)
        sort.Sort(nodelist)
    if l > 20 {
    nodelist.Cut(20,l-1)
    }
    fmt.Printf("End of iterative node\nReturning nodelist with length of=%d\n", nodelist.Len())
    return nodelist
}


func (this *Node) IterativeFindValue(key Key) (*Bucket, []byte) {
    fmt.Printf("IterativeFindValue\n")
    hasnodes := this.FindCloseNodes(key)
    
    cancel := new(bool)
    *cancel = false
    
    ch := make(chan bool)
    done := make (chan bool)
    

    async := NewAtom()
    var shortlist *Bucket
    nodelist := NewBucket(this)
    closest := make(Key, 20)
    alreadyAsked := NewBucket(this)
    var value []byte
    shortlist=hasnodes
    fmt.Printf("Length of shortlist = %d\n", shortlist.Len())
     at := 0
    for {

    go func() {
        for i:= at; i < shortlist.Len()  && i < at+Alpha; i++ {

                ic := i
                go func() {
                    if value != nil { return }
                    defer func() {ch <- false; at++}()
                    fmt.Printf("hasnodes.At(%d)\n", ic)
                    inode :=  shortlist.At(ic)
                    if inode != nil {
                        already := false
                        jlen := alreadyAsked.Len()
                        async.Do(func() {
                            for j:= 0; j<jlen; j++ {

                                m := alreadyAsked.At(j)
                                
                                if bytes.Compare(m.Nodeid, inode.Nodeid) == 0 {already=true; break}
                            }
                           if !already {
                                alreadyAsked.Push(inode)
                                
                            }
                        })
                        if !already {
                            fmt.Printf("Asking peer %x\n", keytobyte(inode.Nodeid))
                            nodes,v := inode.Session.FindValue(key)
                            if v != nil {
                               value = v
                               ch <-true
                               done <- true
                               return
                               
                            }
                            closer := false
                            if nodes == nil {return }
                             len :=  nodes.Len()
                            async.Do(func() { 

                                for j:=0; j<len; j++ {

                                    n := nodes.At(j)
                                    
                                    donotadd := false
                                    if bytes.Compare(n.Nodeid, this.Nodeid) == 0 { donotadd = true }
                                    for k := 0; k < nodelist.Len(); k++ {
                                        if bytes.Compare(n.Nodeid, nodelist.At(k).Nodeid) == 0   { donotadd = true; }
                                    }
                                    if !donotadd {
                                        nodelist.Push(n)
                                    }
                                    if XOR(n.Nodeid, key).Less( XOR(closest, key) )  {
                                        closer =true
                                    }
                                }
                            })
                            if closer {
                                ch <- true
                            }
                        }

                    }
                }()
        }
        closer := false
        for i:= 0; i < shortlist.Len()  && i < Alpha; i++ {
            fmt.Printf("i = %d\n", i)
            a := <-ch
            if a {closer = true}
        }
        done <-closer
      }()
    fmt.Printf("waiting\n")
    a := <-done
    
    fmt.Printf("done waiting\n")

    if a { 
        nodelist.SetSortKey(key)
        sort.Sort(nodelist)
        shortlist := NewBucket(this)
        for i := 0; i < 20 && i < nodelist.Len(); i++ {

        shortlist.Push(nodelist.At(i))

        }
        at = 0
        if value != nil {
            break
        }
        continue
    } else if at+Alpha > shortlist.Len() {
        break
    } else {
       at += Alpha
       fmt.Print("Continuing ... shortlist.Len() = %d\n", shortlist.Len())
       continue
    }
    }
    l := nodelist.Len()
        nodelist.SetSortKey(key)
        sort.Sort(nodelist)
    if l > 20 {
    nodelist.Cut(20,l-1)
    }
    fmt.Printf("Returning nodelist with length of=%d\n", nodelist.Len())
    return nodelist,value
}



type v_answer struct {
    nodes *Bucket
    value []byte
}


func (this *Node) AcceptStream (port int32) *StreamHandler {
    if _, ok := this.StreamListener.Ports[port]; !ok {
        this.StreamListener.Ports[port] = make(chan *StreamHandler)
    }
    h := <-this.StreamListener.Ports[port]
    go h.Start()
    return h
}
func (this *Node) IterativeStore(key Key, value io.Reader) {
    closenodes := this.IterativeFindNode(key)
    fmt.Printf("back from iterativefindnode\n")
    len := closenodes.Len()
    for i:= 0; i<len; i++ {
        //fmt.Printf("Trying to STORE on %s\n", m.Session.RAddr)
        closenodes.At(i).Session.Store(key, value)
    }
}

func (this *Node) MoveKeyToTop(key Key) {
    h := NewHot(func(shared map[string]interface{}){
        self := shared["self"].(*GenericHot)
            distance := XOR(key,this.Nodeid)
            no := int(BucketNo(distance))
            b,ok := this.Buckets[no]
            if b == nil || !ok {return }
            len := b.Len()
            var position int = 0
            for i := 0; i<len; i++ {

                m := b.At(i)
                if bytes.Compare(key,m.Nodeid) == 0 { position = i }
            }
            for i := position; i>0; i-- {
                this.Buckets[no].Swap(i, i-1)
            }        
            self.Answer <- true
    })
    this.QueryHot(h)
    <-h.Answer
    return
}
func GeneratePrivateKey(filename string) {
        os.Open(filename, os.O_CREAT, 0644)
        f,err := os.Open(filename, os.O_WRONLY, 0644)
        if err != nil { fmt.Printf("%s\n", err); return }
        fmt.Printf("Generating key... \n")
        pk,_ := rsa.GenerateKey(rand.Reader, 768)
        fmt.Printf("Done.. Marshalling\n")
        pkdata := x509.MarshalPKCS1PrivateKey(pk)
        fmt.Printf("Done\n")
        _,err = f.Write(pkdata)
                if err != nil { fmt.Printf("%s\n", err); return }
        
        f.Close()
    
}


func (this *Node) Bootstrap(port int, known string, privatekey string) bool {
    knownhost,err := net.ResolveUDPAddr(known)
    if err != nil {
        fmt.Printf("E: %s\n", err)
        return false
    }
    random.Seed(time.Nanoseconds())

    //Establish private key
    f, err := os.Open(privatekey, os.O_RDONLY, 0666) 
    if err != nil {
        return false
    }

        fi,err := os.Stat(privatekey)
    size := int(fi.Size)
    pkdata := make([]byte, size)
    f.Read(pkdata)

    keypair,err :=  x509.ParsePKCS1PrivateKey(pkdata)
            if err != nil { fmt.Printf("%s\n", err); return false }
    this.Keypair = keypair
    
    sha1hash := sha1.New()
    sha1hash.Write(this.Keypair.PublicKey.N.Bytes())
    this.Nodeid = Key(sha1hash.Sum())
    fmt.Printf("This nodes id: %x\n", keytobyte(this.Nodeid))
    this.Reachable = true
   
    
    //Start the listener
    fmt.Printf("Starting the UDPHandler..\n")
    udphandler := NewUDPHandler(port,this)
    this.Handler = udphandler
    go udphandler.Start()
    
    
    //Connect to known host
    fmt.Printf("Connecting to known host\n")
    if err != nil { fmt.Printf("%s\n", err) }
    c := NewUDPSession(knownhost,this,udphandler)
    c.Node = this
    c.NodeIsAdded = false
    c.NeedToSendDesc = true
    c.Start()
    
    c.FindNode(this.Nodeid)
    this.IterativeFindNode(this.Nodeid)
    
    return true
}

func keytobyte(key Key) []byte {
    return key
}
func Bytetokey(key []byte) Key {
    return key
}

func bytetobuf(b []byte) Buf {
    return b
}
