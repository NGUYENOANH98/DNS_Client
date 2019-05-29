package mmt;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;



public class DNSClient {
    
    public ArrayList DNSC(String domain) throws UnknownHostException, IOException {
        InetAddress Server = InetAddress.getByName("8.8.8.8");
        
        //List IP
        ArrayList listIp = new ArrayList();
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        DataOutputStream dos = new DataOutputStream(baos);

        // --- Viết khuôn dạng thông điệp DNS query --- 
        
        //Phần Header 
        
        // Viết ID của gói tin 
        dos.writeShort(0x1809);

        // Viết trường flag
        dos.writeShort(0x0100);

        // Viết trường QDCOUNT
        dos.writeShort(0x0001);

        // Viết trường ANCOUNT
        dos.writeShort(0x0000);

        //Trường NSCOUNT
        dos.writeShort(0x0000);

        //Trường ARCOUNT
        dos.writeShort(0x0000);

        //Phần Question
        
        //Phần QNAME
        String[] domainLabel = domain.split("\\.");
        for (int i = 0; i<domainLabel.length; i++) {
            byte[] domainBytes = domainLabel[i].getBytes("UTF-8");
            dos.writeByte(domainBytes.length);
            dos.write(domainBytes);
        }
        dos.writeByte(0x00);

        //QTYPE
        dos.writeShort(0x0001);

        //QCLASS
        dos.writeShort(0x0001); 

        byte[] queryFrame = baos.toByteArray();

        // Gửi gói tin query
        try(DatagramSocket UDPSocket = new DatagramSocket()){ 
            //set timeout cho socket la 1000ms
            UDPSocket.setSoTimeout(1000);  
            DatagramPacket queryPacket = new DatagramPacket(queryFrame, queryFrame.length, Server, 53);
        
            //Kiểm tra gói tin gửi thành công hay không
            try{
                UDPSocket.send(queryPacket);
            }
            catch(Exception e){
                listIp.add("No Internet !");
                return listIp;
            }

            byte[] buff = new byte[1024];
        
            DatagramPacket responsePacket = new DatagramPacket(buff, buff.length);
        
            //Nhận Response
            UDPSocket.receive(responsePacket);

            DataInputStream din = new DataInputStream(new ByteArrayInputStream(buff));

            //---- Đọc gói tin response -----
        
            //Đọc Header
        
            //ID
            din.readShort();
      
            //Flag
            din.readShort();
        
            //QDCOUNT
            din.readShort();
        
            //ANCOUNT
            short RRs = din.readShort();
        
            //NSCOUNT
            din.readShort();

            //ARCOUNT
            din.readShort();
        
            //Question
        
            //QNAME
            int recLen = 0;
            while ((recLen = din.readByte()) > 0) {
                byte[] record = new byte[recLen];
                for (int i = 0; i < recLen; i++) {
                    record[i] = din.readByte();
                }
            }

           //QTYPE
           din.readShort();

           //QCLASS
           din.readShort();
        
           //ANSWER
        
           //RRs
            int count = 0 ; // số địa chỉ IP
            for(int i = 0 ; i< RRs ; i++){ 
                String ip = "";
                //NAME
                din.readShort();
                //TYPE
                short type = din.readShort();
                //CLASS
                din.readShort();
                //TTL
                din.readInt();
                //RLENGTH
                short len = din.readShort();
                //RDATA
                if(type == 1) {
                    for (int j = 0; j < len; j++) {
                    //Khi type là A thì mới đọc IP
                    //&0xFF để chuyển kiểu int thành unsignedInt
                        ip += "" + String.format("%d", (din.readByte() & 0xFF)) + ".";
                    }
                //Thêm địa chỉ IP vào list
                    listIp.add(ip);

                    count ++;
                }
                else{
                    //Không phải kiểu A,không đọc IP
                        for(int j = 0 ; j < len ; j++){
                            din.readByte();
                        }
                    }

            }

            if(count == 0) //Khi không tồn tại IP nào
                listIp.add("Not Exist !");
            UDPSocket.close();
        }
        catch(SocketTimeoutException e){
            //timeout
            listIp.add("No Internet !");
            return listIp;
        }
        return listIp;
    }  
}
