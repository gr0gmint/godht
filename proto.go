package dht

import "goprotobuf.googlecode.com/hg/proto"
import binary "encoding/binary"

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
    tmp,ok := this.Buffer[8:8+hdrlen]
    if !ok {
        //this.Conn.Close()
        return nil,nil,addr,err
    }
    copy(hdrdata,tmp)
    header := NewHeader()
    err = proto.Unmarshal(hdrdata, header)
    if err != nil {
        return nil,nil,addr,err
    }
    tmp,ok = this.Buffer[8+hdrlen:8+hdrlen+datalen]
    if !ok {
        return nil,nil,addr,err
    }
    copy(newdata,tmp)
    
    
    return header, newdata,nil
}
 
func (this *Node) EncodePacket(data []byte, t,id,part int32, first,hmac bool) []byte {
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
