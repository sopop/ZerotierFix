package net.kaaass.zerotierfix.service;

import android.util.Log;

import com.zerotier.sdk.Node;
import com.zerotier.sdk.VirtualNetworkConfig;
import com.zerotier.sdk.util.StringUtils;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Handles ARP resolution for ZeroTier virtual networks.
 * This class provides the necessary methods to integrate with TunTapAdapter's
 * ARP logic, primarily by wrapping ZeroTier's internal MAC resolution.
 */
public class TunTapARPTable {
    private static final String TAG = "TunTapARPTable";
    private final Node node;
    private final long networkId;

    // Cache for resolved MACs (simple implementation)
    private final ConcurrentHashMap<InetAddress, Long> arpCache = new ConcurrentHashMap<>();

    public TunTapARPTable(Node node, long networkId) {
        this.node = node;
        this.networkId = networkId;
    }

    /**
     * Called when the virtual network configuration changes.
     * @param config The new network configuration.
     */
    public void onVirtualNetworkConfigChanged(VirtualNetworkConfig config) {
        Log.d(TAG, "Virtual network config changed for " + StringUtils.toHexString(networkId));
        this.arpCache.clear();
        // In a complete implementation, this would handle local IP/MAC mapping updates.
    }

    /**
     * Attempts to find the MAC address for a given IP address using ZeroTier's internal lookup.
     * @param destAddress The destination IP address.
     * @return The MAC address (long) or 0 if not immediately known (needs ARP broadcast).
     */
    public long lookup(InetAddress destAddress) {
        try {
            int bits = destAddress.getAddress().length == 4 ? 24 : 120; // Default mask for ZT lookup
            
            // Rely on the ZeroTier SDK to resolve the MAC address for the member IP
            long mac = node.lookupMac(networkId, destAddress.getAddress(), bits);

            if (mac != 0) {
                arpCache.put(destAddress, mac);
            }
            return mac;

        } catch (Exception e) {
            Log.e(TAG, "Error looking up MAC for " + destAddress.getHostAddress(), e);
            return 0;
        }
    }

    /**
     * Builds an Ethernet frame containing an ARP request for the target IP.
     * @param destAddress The target IP address.
     * @param localMac The MAC address of the requesting interface.
     * @return A ByteBuffer containing the full Ethernet frame with the ARP request.
     */
    public ByteBuffer buildARPRequest(InetAddress destAddress, long localMac) {
        // ARP Request Construction (Simplified)
        ByteBuffer buffer = ByteBuffer.allocate(42); // 14 bytes Eth Header + 28 bytes ARP Payload
        buffer.order(ByteOrder.BIG_ENDIAN); // Network byte order

        long broadcastMac = 0xFFFFFFFFFFFFL; 
        
        // 1. Ethernet Header (14 bytes)
        buffer.putLong(broadcastMac << 16); buffer.position(6);
        buffer.putLong(localMac << 16); buffer.position(12);
        buffer.putShort((short) 0x0806); // EtherType (ARP)

        // 2. ARP Payload (28 bytes)
        buffer.putShort((short) 1); // Hardware Type (Ethernet)
        buffer.putShort((short) 0x0800); // Protocol Type (IPv4)
        buffer.put((byte) 6); // Hardware Address Length
        buffer.put((byte) 4); // Protocol Address Length
        buffer.putShort((short) 1); // Opcode (Request)
        buffer.putLong(localMac << 16); buffer.position(28); // Sender Hardware Address
        buffer.put(new byte[]{0, 0, 0, 0}); // Placeholder Sender IP (ZT handles the actual source IP)
        buffer.putLong(0L); buffer.position(38); // Target Hardware Address (Zeroed)
        buffer.put(destAddress.getAddress()); // Target Protocol Address

        buffer.flip();
        return buffer;
    }

    /**
     * Processes an incoming ARP packet and updates the local cache if it is a reply.
     * For simplicity, this implementation relies on the ZT Node for replies for local IPs
     * and only processes incoming replies to update the cache.
     * @param arpFrame The ByteBuffer containing the incoming Ethernet frame with ARP payload.
     * @return Always returns null, relying on ZT's internal mechanism for replies.
     */
    public ByteBuffer processARPPacket(ByteBuffer arpFrame) {
        try {
            arpFrame.rewind();
            arpFrame.order(ByteOrder.BIG_ENDIAN);

            if (arpFrame.limit() < 42) return null;

            short opCode = arpFrame.getShort(20);
            
            if (opCode == 2) { // ARP Reply received
                // Extract Sender MAC
                byte[] senderMacBytes = new byte[6];
                arpFrame.position(14 + 8); 
                arpFrame.get(senderMacBytes); 
                
                long senderMac = 0;
                for (int i = 0; i < 6; i++) {
                    senderMac = (senderMac << 8) | (senderMacBytes[i] & 0xFF);
                }
                
                // Extract Sender IP
                byte[] senderIpBytes = new byte[4];
                arpFrame.get(senderIpBytes);
                InetAddress senderIp = InetAddress.getByAddress(senderIpBytes);
                
                Log.d(TAG, "ARP Reply received and cached: IP=" + senderIp.getHostAddress() + ", MAC=" + StringUtils.toHexString(senderMac));
                arpCache.put(senderIp, senderMac);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error processing ARP packet", e);
        }
        
        return null; 
    }
}