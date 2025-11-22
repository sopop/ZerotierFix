package net.kaaass.zerotierfix.service;

import android.os.ParcelFileDescriptor;
import android.support.v4.media.session.PlaybackStateCompat;
import android.system.Os;
import android.util.Log;

import com.zerotier.sdk.Node;
import com.zerotier.sdk.ResultCode;
import com.zerotier.sdk.VirtualNetworkConfig;
import com.zerotier.sdk.VirtualNetworkFrameListener;
import com.zerotier.sdk.util.StringUtils;

import net.kaaass.zerotierfix.util.DebugLog;
import net.kaaass.zerotierfix.util.IPPacketUtils;
import net.kaaass.zerotierfix.util.InetAddressUtils;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.util.HashMap;
import java.util.Objects;

// TODO: clear up
public class TunTapAdapter implements VirtualNetworkFrameListener {
    public static final String TAG = "TunTapAdapter";
    private static final int ARP_PACKET = 2054;
    private static final int IPV4_PACKET = 2048;
    private static final int IPV6_PACKET = 34525;
    private final Node node;
    private final long networkId;
    private final FileChannel vpnOutFileChannel;
    private final ZeroTierOneService ztService;
    private final TunTapARPTable arpTable;
    private final HashMap<Route, Long> routeMap;

    TunTapAdapter(ZeroTierOneService zeroTierOneService, long j, ParcelFileDescriptor parcelFileDescriptor) {
        this.networkId = j;
        this.ztService = zeroTierOneService;
        this.node = zeroTierOneService.getNode();
        this.vpnOutFileChannel = parcelFileDescriptor.getFileDescriptor() == null ? null : new java.io.FileOutputStream(parcelFileDescriptor.getFileDescriptor()).getChannel();
        this.arpTable = new TunTapARPTable(this.node, j);
        this.routeMap = new HashMap<>();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void addRoute(Route route) {
        synchronized (this.routeMap) {
            this.routeMap.put(route, this.networkId);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void removeRoute(Route route) {
        synchronized (this.routeMap) {
            this.routeMap.remove(route);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void clearRoutes() {
        synchronized (this.routeMap) {
            this.routeMap.clear();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void close() {
        try {
            if (this.vpnOutFileChannel != null) {
                this.vpnOutFileChannel.close();
            }
        } catch (IOException e) {
            Log.e(TAG, "Error closing vpnOutFileChannel: " + e.getMessage(), e);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void onVirtualNetworkConfigChanged(VirtualNetworkConfig virtualNetworkConfig) {
        this.arpTable.onVirtualNetworkConfigChanged(virtualNetworkConfig);
    }

    private void handleIPv4Packet(long localMac, long nextDeadline, ByteBuffer byteBuffer,
                                  InetAddress destAddress) throws UnknownHostException {
        if (!this.node.hasRoute(this.networkId, destAddress.getAddress(), 24)) {
            // Check for ARP or Route
            var route = routeForDestination(destAddress);
            if (route == null) {
                Log.e(TAG, "No route found for destination: " + destAddress);
                return;
            }
            if (route.isARPNeeded()) {
                var destMac = this.arpTable.lookup(destAddress);
                if (destMac == 0) {
                    var arpReqPacket = this.arpTable.buildARPRequest(destAddress, localMac);
                    if (arpReqPacket == null) {
                        Log.e(TAG, "Error building ARP request packet for " + destAddress);
                        return;
                    }

                    // 修复: 将 ByteBuffer 转换为 byte[]
                    var arpDataArray = new byte[arpReqPacket.remaining()];
                    arpReqPacket.get(arpDataArray);

                    var result = this.node.processVirtualNetworkFrame(System.currentTimeMillis(), this.networkId, localMac, destMac, ARP_PACKET, 0, arpDataArray, nextDeadline); // 使用 byte[]
                    if (result != ResultCode.RESULT_OK) {
                        Log.e(TAG, "processVirtualNetworkFrame for ARP returned: " + result.toString());
                        this.ztService.shutdown();
                    }
                    this.ztService.setNextBackgroundTaskDeadline(nextDeadline);
                    return;
                }

                // 修复: 将 ByteBuffer 转换为 byte[]
                var dataArray = new byte[byteBuffer.remaining()];
                byteBuffer.get(dataArray);

                // 重新设置byteBuffer，以便在发送后不影响原始逻辑
                byteBuffer.rewind();

                var result = this.node.processVirtualNetworkFrame(System.currentTimeMillis(), this.networkId, localMac, destMac, IPV4_PACKET, 0, dataArray, nextDeadline); // 使用 byte[]
                if (result != ResultCode.RESULT_OK) {
                    Log.e(TAG, "processVirtualNetworkFrame returned: " + result.toString());
                    this.ztService.shutdown();
                }
                this.ztService.setNextBackgroundTaskDeadline(nextDeadline);
            }
        } else {
            // Direct Route
            long destMac = this.node.lookupMac(this.networkId, destAddress.getAddress(), 24);

            // 修复: 将 ByteBuffer 转换为 byte[]
            var dataArray = new byte[byteBuffer.remaining()];
            byteBuffer.get(dataArray);

            // 重新设置byteBuffer，以便在发送后不影响原始逻辑
            byteBuffer.rewind();

            var result = this.node.processVirtualNetworkFrame(System.currentTimeMillis(), this.networkId, localMac, destMac, IPV4_PACKET, 0, dataArray, nextDeadline); // 使用 byte[]
            if (result != ResultCode.RESULT_OK) {
                Log.e(TAG, "processVirtualNetworkFrame returned: " + result.toString());
                this.ztService.shutdown();
            }
            this.ztService.setNextBackgroundTaskDeadline(nextDeadline);
        }
    }

    private void handleIPv6Packet(long localMac, long nextDeadline, ByteBuffer byteBuffer,
                                  InetAddress destAddress) throws UnknownHostException {
        if (!this.node.hasRoute(this.networkId, destAddress.getAddress(), 120)) {
            // Check for Route
            var route = routeForDestination(destAddress);
            if (route == null) {
                Log.e(TAG, "No route found for destination: " + destAddress);
                return;
            }

            // 修复: 将 ByteBuffer 转换为 byte[]
            var dataArray = new byte[byteBuffer.remaining()];
            byteBuffer.get(dataArray);

            // 重新设置byteBuffer，以便在发送后不影响原始逻辑
            byteBuffer.rewind();

            var result = this.node.processVirtualNetworkFrame(System.currentTimeMillis(), this.networkId, localMac, 0, IPV6_PACKET, 0, dataArray, nextDeadline); // 使用 byte[]
            if (result != ResultCode.RESULT_OK) {
                Log.e(TAG, "processVirtualNetworkFrame returned: " + result.toString());
                this.ztService.shutdown();
            }
            this.ztService.setNextBackgroundTaskDeadline(nextDeadline);
        } else {
            // Direct Route
            long destMac = this.node.lookupMac(this.networkId, destAddress.getAddress(), 120);

            // 修复: 将 ByteBuffer 转换为 byte[]
            var dataArray = new byte[byteBuffer.remaining()];
            byteBuffer.get(dataArray);

            // 重新设置byteBuffer，以便在发送后不影响原始逻辑
            byteBuffer.rewind();

            var result = this.node.processVirtualNetworkFrame(System.currentTimeMillis(), this.networkId, localMac, destMac, IPV6_PACKET, 0, dataArray, nextDeadline); // 使用 byte[]
            if (result != ResultCode.RESULT_OK) {
                Log.e(TAG, "processVirtualNetworkFrame returned: " + result.toString());
                this.ztService.shutdown();
            }
            this.ztService.setNextBackgroundTaskDeadline(nextDeadline);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void handleVirtualNetworkFrame(long localMac, long nextDeadline, ByteBuffer byteBuffer) {
        if (byteBuffer.remaining() >= 14) {
            int etherType = byteBuffer.getChar(12) & 65535;
            InetAddress destAddress;

            try {
                switch (etherType) {
                    case IPV4_PACKET:
                        destAddress = InetAddressUtils.getDestIPv4(byteBuffer);
                        handleIPv4Packet(localMac, nextDeadline, byteBuffer, destAddress);
                        break;
                    case IPV6_PACKET:
                        destAddress = InetAddressUtils.getDestIPv6(byteBuffer);
                        handleIPv6Packet(localMac, nextDeadline, byteBuffer, destAddress);
                        break;
                    case ARP_PACKET:
                        // ARP does not require address lookup, it is handled internally
                        // 修复: 将 ByteBuffer 转换为 byte[]
                        var arpDataArray = new byte[byteBuffer.remaining()];
                        byteBuffer.get(arpDataArray);

                        // 重新设置byteBuffer，以便在发送后不影响原始逻辑
                        byteBuffer.rewind();

                        var result = this.node.processVirtualNetworkFrame(System.currentTimeMillis(), this.networkId, localMac, 0, ARP_PACKET, 0, arpDataArray, nextDeadline); // 使用 byte[]
                        if (result != ResultCode.RESULT_OK) {
                            Log.e(TAG, "processVirtualNetworkFrame for ARP returned: " + result.toString());
                            this.ztService.shutdown();
                        }
                        this.ztService.setNextBackgroundTaskDeadline(nextDeadline);
                        break;
                    default:
                        Log.d(TAG, "Unknown Packet Type Received: 0x" + String.format("%04X", etherType));
                        break;
                }
            } catch (Exception e) {
                Log.e(TAG, "Error handling packet: " + e.getMessage(), e);
            }
        }
    }


    // 修复: 调整方法签名以匹配新的 VirtualNetworkFrameListener 接口 (ByteBuffer -> byte[])
    @Override
    public void onVirtualNetworkFrame(long networkId, long srcMac, long destMac, long etherType,
                                      long vlanId, byte[] frameData) { 
        // 将 byte[] 包装为 ByteBuffer 以兼容旧逻辑
        ByteBuffer frameBuffer = ByteBuffer.wrap(frameData);
        frameBuffer.order(ByteOrder.nativeOrder()); // 确保字节序正确

        DebugLog.d(TAG, "onVirtualNetworkFrame: NetID: " + StringUtils.toHexString(networkId) +
                " SrcMAC: " + StringUtils.toHexString(srcMac) +
                " DestMAC: " + StringUtils.toHexString(destMac) +
                " EtherType: " + etherType +
                " VLAN ID: " + vlanId + " Frame Length: " + frameBuffer.remaining());

        if (etherType == ARP_PACKET) {
            // 修复: 传递 frameBuffer (ByteBuffer)
            var arpReply = this.arpTable.processARPPacket(frameBuffer);
            if (arpReply != null) {
                try {
                    // 修复: 将 ByteBuffer 转换为 byte[]
                    var arpReplyData = new byte[arpReply.remaining()];
                    arpReply.get(arpReplyData);

                    long[] nextDeadline = new long[1];
                    var result = this.node.processVirtualNetworkFrame(System.currentTimeMillis(), this.networkId, destMac, srcMac, ARP_PACKET, 0,
                            arpReplyData, nextDeadline); // 使用 byte[]
                    if (result != ResultCode.RESULT_OK) {
                        Log.e(TAG, "processVirtualNetworkFrame for ARP reply returned: " + result.toString());
                        this.ztService.shutdown();
                    }
                    this.ztService.setNextBackgroundTaskDeadline(nextDeadline[0]);
                } catch (Exception e) {
                    Log.e(TAG, "Error processing ARP reply: " + e.getMessage(), e);
                }
            }
        } else if (etherType == IPV4_PACKET) {
            DebugLog.d(TAG, "Got IPv4 packet. Length: " + frameBuffer.remaining() + " Bytes");
            try {
                // 修复: 传递 frameBuffer (ByteBuffer)
                frameBuffer.rewind();
                var sourceIP = IPPacketUtils.getSourceIP(frameBuffer);
                frameBuffer.rewind();
                var destIP = IPPacketUtils.getDestIP(frameBuffer);

                if (this.ztService.getLocalMac() == destMac) {
                    // Destination is local (or broadcast), write to TUN
                    frameBuffer.rewind();
                    // 修复: 传递 frameBuffer (ByteBuffer)
                    int written = this.vpnOutFileChannel.write(frameBuffer);
                    if (written == -1) {
                        Log.e(TAG, "Error writing data to vpn socket: " + written);
                    } else if (frameBuffer.remaining() > 0) {
                        Log.e(TAG, "Error writing data to vpn socket: written: " + written + " remaining " + frameBuffer.remaining());
                    }
                } else if (destMac == -1) {
                    // IPv4 broadcast?
                    frameBuffer.rewind();
                    // 修复: 传递 frameBuffer (ByteBuffer)
                    int written = this.vpnOutFileChannel.write(frameBuffer);
                    if (written == -1) {
                        Log.e(TAG, "Error writing data to vpn socket: " + written);
                    } else if (frameBuffer.remaining() > 0) {
                        Log.e(TAG, "Error writing data to vpn socket: written: " + written + " remaining " + frameBuffer.remaining());
                    }
                } else {
                    Log.d(TAG, "onVirtualNetworkFrame: Packet not for me. DestMAC: " + StringUtils.toHexString(destMac));
                }
            } catch (Exception e) {
                Log.e(TAG, "Error writing data to vpn socket: " + e.getMessage(), e);
            }
        } else if (etherType == IPV6_PACKET) {
            DebugLog.d(TAG, "Got IPv6 packet. Length: " + frameBuffer.remaining() + " Bytes");
            try {
                // 修复: 传递 frameBuffer (ByteBuffer)
                frameBuffer.rewind();
                var sourceIP = IPPacketUtils.getSourceIP(frameBuffer);
                frameBuffer.rewind();
                var destIP = IPPacketUtils.getDestIP(frameBuffer);

                if (this.ztService.getLocalMac() == destMac) {
                    // Destination is local (or broadcast), write to TUN
                    frameBuffer.rewind();
                    // 修复: 传递 frameBuffer (ByteBuffer)
                    int written = this.vpnOutFileChannel.write(frameBuffer);
                    if (written == -1) {
                        Log.e(TAG, "Error writing data to vpn socket: " + written);
                    } else if (frameBuffer.remaining() > 0) {
                        Log.e(TAG, "Error writing data to vpn socket: written: " + written + " remaining " + frameBuffer.remaining());
                    }
                } else if (destMac == -1) {
                    // IPv6 multicast or broadcast?
                    frameBuffer.rewind();
                    // 修复: 传递 frameBuffer (ByteBuffer)
                    int written = this.vpnOutFileChannel.write(frameBuffer);
                    if (written == -1) {
                        Log.e(TAG, "Error writing data to vpn socket: " + written);
                    } else if (frameBuffer.remaining() > 0) {
                        Log.e(TAG, "Error writing data to vpn socket: written: " + written + " remaining " + frameBuffer.remaining());
                    }
                } else {
                    Log.d(TAG, "onVirtualNetworkFrame: Packet not for me. DestMAC: " + StringUtils.toHexString(destMac));
                }
            } catch (Exception e) {
                Log.e(TAG, "Error writing data to vpn socket: " + e.getMessage(), e);
            }
        } else if (frameBuffer.remaining() >= 14) {
            // 修复: 从 ByteBuffer 读取
            Log.d(TAG, "Unknown Packet Type Received: 0x" + String.format("%02X%02X", frameBuffer.get(12), frameBuffer.get(13)));
        } else {
            // 修复: 从 ByteBuffer 读取
            Log.d(TAG, "Unknown Packet Received.  Packet Length: " + frameBuffer.remaining());
        }
    }

    private Route routeForDestination(InetAddress destAddress) {
        synchronized (this.routeMap) {
            for (var route : this.routeMap.keySet()) {
                if (route.belongsToRoute(destAddress)) {
                    return route;
                }
            }
            return null;
        }
    }

    private long networkIdForDestination(InetAddress destAddress) {
        synchronized (this.routeMap) {
            for (Route route : this.routeMap.keySet()) {
                if (route.belongsToRoute(destAddress)) {
                    return Objects.requireNonNull(this.routeMap.get(route));
                }
            }
            return 0L;
        }
    }
}