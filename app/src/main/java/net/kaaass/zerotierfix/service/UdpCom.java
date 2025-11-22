package net.kaaass.zerotierfix.service;

import android.util.Log;

import com.zerotier.sdk.Node;
import com.zerotier.sdk.PacketSender;
import com.zerotier.sdk.ResultCode;

import net.kaaass.zerotierfix.util.DebugLog;

import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

// TODO: clear up
public class UdpCom implements PacketSender, Runnable {
    private static final String TAG = "UdpCom";
    private Node node;
    private final DatagramChannel svrChannel;
    private final ZeroTierOneService ztService;

    UdpCom(ZeroTierOneService zeroTierOneService, DatagramChannel datagramChannel) {
        this.svrChannel = datagramChannel;
        this.ztService = zeroTierOneService;
    }

    public void setNode(Node node2) {
        this.node = node2;
    }

    // 修复: 调整方法签名以匹配新的 PacketSender 接口 (ByteBuffer -> byte[])
    @Override // com.zerotier.sdk.PacketSender
    public int onSendPacketRequested(long j, InetSocketAddress inetSocketAddress, byte[] bArr, int i) { // **修改: ByteBuffer -> byte[]**
        if (this.svrChannel == null) {
            Log.e(TAG, "Attempted to send packet on a null channel: " + inetSocketAddress.toString());
            return -1;
        }
        try {
            // 修复: 将 byte[] 包装为 ByteBuffer 以发送
            ByteBuffer buf = ByteBuffer.wrap(bArr);
            DebugLog.d(TAG, "onSendPacketRequested: Sent " + buf.remaining() + " bytes to " + inetSocketAddress.toString());
            this.svrChannel.send(buf, inetSocketAddress); // 发送 ByteBuffer
            return 0;
        } catch (Exception unused) {
            return -1;
        }
    }

    public void run() {
        Log.d(TAG, "UDP Listen Thread Started.");
        try {
            long[] jArr = new long[1];
            ByteBuffer buf = ByteBuffer.allocateDirect(16384);
            while (this.svrChannel.isOpen()) {
                jArr[0] = 0;
                try {
                    SocketAddress recvSockAddr = this.svrChannel.receive(buf);
                    buf.flip();
                    if (buf.remaining() > 0) {
                        DebugLog.d(TAG, "Got " + buf.remaining() + " Bytes From: " + recvSockAddr);
                        
                        // 修复: 将 ByteBuffer 转换为 byte[] 以便调用 processWirePacket
                        var dataArray = new byte[buf.remaining()];
                        buf.get(dataArray);

                        ResultCode processWirePacket = this.node.processWirePacket(System.currentTimeMillis(), -1, (InetSocketAddress) recvSockAddr, dataArray, jArr); // 使用 byte[]
                        if (processWirePacket != ResultCode.RESULT_OK) {
                            Log.e(TAG, "processWirePacket returned: " + processWirePacket.toString());
                            this.ztService.shutdown();
                        }
                        this.ztService.setNextBackgroundTaskDeadline(jArr[0]);
                    }
                    buf.clear();
                } catch (SocketTimeoutException ignored) {
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        Log.d(TAG, "UDP Listen Thread Ended.");
    }
}