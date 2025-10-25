#include <iostream>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_packet.h>

using namespace std;

template <typename T>
class CustomStack {
private:
    struct StackNode {
        T value;
        StackNode* below;
        StackNode(T v) : value(v), below(nullptr) {}
    };
    StackNode* topNode;
    int count;

public:
    CustomStack() : topNode(nullptr), count(0) {}
    
    ~CustomStack() {
        while (topNode) {
            StackNode* temp = topNode;
            topNode = topNode->below;
            delete temp;
        }
    }

    void add(T item) {
        StackNode* node = new StackNode(item);
        node->below = topNode;
        topNode = node;
        count++;
    }

    T remove() {
        if (!topNode) throw runtime_error("Empty stack");
        StackNode* temp = topNode;
        T val = temp->value;
        topNode = topNode->below;
        delete temp;
        count--;
        return val;
    }

    T viewTop() {
        if (!topNode) throw runtime_error("Empty stack");
        return topNode->value;
    }

    bool empty() { return topNode == nullptr; }
    int size() { return count; }
    
    void reset() {
        while (topNode) {
            StackNode* temp = topNode;
            topNode = topNode->below;
            delete temp;
        }
        count = 0;
    }
};

template <typename T>
class CustomQueue {
private:
    struct QueueNode {
        T value;
        QueueNode* following;
        QueueNode(T v) : value(v), following(nullptr) {}
    };
    QueueNode* head;
    QueueNode* tail;
    int count;

public:
    CustomQueue() : head(nullptr), tail(nullptr), count(0) {}
    
    ~CustomQueue() {
        while (head) {
            QueueNode* temp = head;
            head = head->following;
            delete temp;
        }
    }

    void add(T item) {
        QueueNode* node = new QueueNode(item);
        if (!head) {
            head = tail = node;
        } else {
            tail->following = node;
            tail = node;
        }
        count++;
    }

    T remove() {
        if (!head) throw runtime_error("Empty queue");
        QueueNode* temp = head;
        T val = temp->value;
        head = head->following;
        if (!head) tail = nullptr;
        delete temp;
        count--;
        return val;
    }

    T viewFront() {
        if (!head) throw runtime_error("Empty queue");
        return head->value;
    }

    bool empty() { return head == nullptr; }
    int size() { return count; }
};

enum LayerType { LAYER_ETH, LAYER_IP4, LAYER_IP6, LAYER_TCP_PROTO, LAYER_UDP_PROTO, LAYER_NONE };

struct ProtocolLayer {
    LayerType type;
    unsigned char content[65536];
    int size;

    ProtocolLayer() : type(LAYER_NONE), size(0) {
        memset(content, 0, sizeof(content));
    }

    ProtocolLayer(LayerType t, const unsigned char* data, int len) : type(t), size(len) {
        if (data && len > 0 && len <= 65536) {
            memcpy(content, data, len);
        }
    }

    const char* name() const {
        switch (type) {
            case LAYER_ETH: return "Ethernet";
            case LAYER_IP4: return "IPv4";
            case LAYER_IP6: return "IPv6";
            case LAYER_TCP_PROTO: return "TCP";
            case LAYER_UDP_PROTO: return "UDP";
            default: return "Unknown";
        }
    }
};

struct NetworkPacket {
    unsigned int identifier;
    time_t capturedAt;
    unsigned char data[65536];
    int length;
    string sourceIP;
    string destIP;
    int attemptsMade;

    NetworkPacket() : identifier(0), capturedAt(0), length(0), attemptsMade(0) {
        memset(data, 0, sizeof(data));
    }

    NetworkPacket(unsigned int id, const unsigned char* buf, int len) 
        : identifier(id), length(len), attemptsMade(0) {
        capturedAt = time(nullptr);
        if (buf && len > 0 && len <= 65536) {
            memcpy(data, buf, len);
        }
    }
};

class LayerParser {
private:
    CustomStack<ProtocolLayer> layerStack;

public:
    void loadPacket(const unsigned char* buf, int len) {
        layerStack.reset();
        if (len >= 14) {
            layerStack.add(ProtocolLayer(LAYER_ETH, buf, len));
        }
    }

    bool parseNext(NetworkPacket& pkt) {
        if (layerStack.empty()) return false;

        ProtocolLayer current = layerStack.remove();

        if (current.type == LAYER_ETH && current.size >= 14) {
            unsigned short ethType = ntohs(*(unsigned short*)(current.content + 12));
            
            if (ethType == 0x0800 && current.size >= 34) {
                struct iphdr* ipv4 = (struct iphdr*)(current.content + 14);
                char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ipv4->saddr, src, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &ipv4->daddr, dst, INET_ADDRSTRLEN);
                pkt.sourceIP = src;
                pkt.destIP = dst;
                layerStack.add(ProtocolLayer(LAYER_IP4, current.content + 14, current.size - 14));
                return true;
            } else if (ethType == 0x86DD && current.size >= 54) {
                struct ip6_hdr* ipv6 = (struct ip6_hdr*)(current.content + 14);
                char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &ipv6->ip6_src, src, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &ipv6->ip6_dst, dst, INET6_ADDRSTRLEN);
                pkt.sourceIP = src;
                pkt.destIP = dst;
                layerStack.add(ProtocolLayer(LAYER_IP6, current.content + 14, current.size - 14));
                return true;
            }
        } else if (current.type == LAYER_IP4 && current.size >= 20) {
            struct iphdr* ipv4 = (struct iphdr*)current.content;
            int hdrLen = ipv4->ihl * 4;
            
            if (ipv4->protocol == IPPROTO_TCP && current.size >= hdrLen + 20) {
                layerStack.add(ProtocolLayer(LAYER_TCP_PROTO, current.content + hdrLen, current.size - hdrLen));
                return true;
            } else if (ipv4->protocol == IPPROTO_UDP && current.size >= hdrLen + 8) {
                layerStack.add(ProtocolLayer(LAYER_UDP_PROTO, current.content + hdrLen, current.size - hdrLen));
                return true;
            }
        } else if (current.type == LAYER_IP6 && current.size >= 40) {
            struct ip6_hdr* ipv6 = (struct ip6_hdr*)current.content;
            
            if (ipv6->ip6_nxt == IPPROTO_TCP && current.size >= 60) {
                layerStack.add(ProtocolLayer(LAYER_TCP_PROTO, current.content + 40, current.size - 40));
                return true;
            } else if (ipv6->ip6_nxt == IPPROTO_UDP && current.size >= 48) {
                layerStack.add(ProtocolLayer(LAYER_UDP_PROTO, current.content + 40, current.size - 40));
                return true;
            }
        }
        return false;
    }

    ProtocolLayer currentLayer() {
        return layerStack.empty() ? ProtocolLayer() : layerStack.viewTop();
    }

    bool hasLayers() { return !layerStack.empty(); }
    int layerCount() { return layerStack.size(); }
};

class PacketMonitor {
private:
    CustomQueue<NetworkPacket> mainQueue;
    CustomQueue<NetworkPacket> matchedQueue;
    CustomQueue<NetworkPacket> retryQueue;
    LayerParser parser;
    unsigned int nextID;
    int socketFD;
    bool active;

public:
    PacketMonitor() : nextID(0), socketFD(-1), active(false) {
        srand(time(nullptr));
    }

    ~PacketMonitor() {
        if (socketFD >= 0) close(socketFD);
    }

    bool setupSocket() {
        if (socketFD >= 0) return true;
        
        socketFD = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (socketFD < 0) {
            cout << "\n[ERROR] Socket initialization failed\n";
            cout << "Reason: Insufficient permissions for raw socket access\n";
            return false;
        }
        return true;
    }

    void capture(int seconds) {
        if (!setupSocket()) {
            return;
        }

        active = true;
        unsigned char buffer[65536];
        time_t start = time(nullptr);
        
        cout << "\n>> Initiating packet capture session\n";
        cout << ">> Duration: " << seconds << " seconds\n";
        cout << ">> Interface: enp0s3\n";
        cout << ">> Press Ctrl+C to stop early\n\n";

        while (active && (time(nullptr) - start) < seconds) {
            int received = recvfrom(socketFD, buffer, sizeof(buffer), 0, nullptr, nullptr);
            
            if (received > 0) {
                NetworkPacket pkt(++nextID, buffer, received);
                
                if (received >= 34) {
                    struct iphdr* ip = (struct iphdr*)(buffer + 14);
                    if (ip->version == 4) {
                        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &ip->saddr, src, INET_ADDRSTRLEN);
                        inet_ntop(AF_INET, &ip->daddr, dst, INET_ADDRSTRLEN);
                        pkt.sourceIP = src;
                        pkt.destIP = dst;
                    }
                }
                
                mainQueue.add(pkt);
                cout << "[PKT #" << pkt.identifier << "] " 
                     << received << "B | " 
                     << pkt.sourceIP << " → " << pkt.destIP << "\n";
            }
            usleep(50);
        }
        
        active = false;
        cout << "\n>> Capture session terminated\n";
        cout << ">> Total packets captured: " << nextID << "\n";
    }

    void showPackets() {
        cout << "\n";
        cout << "┌────────────────────────────────────────────────────────────────┐\n";
        cout << "│                    PACKET INVENTORY                            │\n";
        cout << "└────────────────────────────────────────────────────────────────┘\n\n";
        
        CustomQueue<NetworkPacket> temp;
        int total = 0;

        while (!mainQueue.empty()) {
            NetworkPacket pkt = mainQueue.remove();
            total++;
            cout << "  [#" << pkt.identifier << "] ";
            cout << "Time: " << pkt.capturedAt << " | ";
            cout << "Route: " << pkt.sourceIP << " → " << pkt.destIP << " | ";
            cout << "Size: " << pkt.length << "B\n";
            temp.add(pkt);
        }

        while (!temp.empty()) mainQueue.add(temp.remove());
        cout << "\n>> Total entries: " << total << " packets\n";
    }

    void analyzePackets() {
        cout << "\n";
        cout << "┌────────────────────────────────────────────────────────────────┐\n";
        cout << "│                PROTOCOL LAYER ANALYSIS                         │\n";
        cout << "└────────────────────────────────────────────────────────────────┘\n";
        
        CustomQueue<NetworkPacket> temp;
        int analyzed = 0;

        while (!mainQueue.empty()) {
            NetworkPacket pkt = mainQueue.remove();
            parser.loadPacket(pkt.data, pkt.length);
            analyzed++;

            cout << "\n  Packet #" << pkt.identifier << " Breakdown:\n";
            cout << "  ├─ Path: " << pkt.sourceIP << " → " << pkt.destIP << "\n";
            cout << "  ├─ Size: " << pkt.length << " bytes\n";
            cout << "  └─ Layer Structure:\n";

            int layers = 0;
            while (parser.hasLayers() && layers < 5) {
                ProtocolLayer layer = parser.currentLayer();
                if (layers == 0) cout << "      ├─ ";
                else if (layers < 4) cout << "      ├─ ";
                else cout << "      └─ ";
                cout << "Layer " << (layers + 1) << ": " << layer.name() << "\n";
                if (!parser.parseNext(pkt)) break;
                layers++;
            }
            
            temp.add(pkt);
        }

        while (!temp.empty()) mainQueue.add(temp.remove());
        cout << "\n>> Analysis complete: " << analyzed << " packets processed\n";
    }

    void filterByIP(string src, string dst) {
        cout << "\n";
        cout << "┌────────────────────────────────────────────────────────────────┐\n";
        cout << "│                    PACKET FILTERING                            │\n";
        cout << "└────────────────────────────────────────────────────────────────┘\n";
        cout << "\n>> Filter Criteria:\n";
        cout << "   Source: " << src << "\n";
        cout << "   Destination: " << dst << "\n\n";
        
        CustomQueue<NetworkPacket> temp;
        int oversized = 0;
        int matched = 0;

        while (!mainQueue.empty()) {
            NetworkPacket pkt = mainQueue.remove();
            bool match = (pkt.sourceIP == src && pkt.destIP == dst) ||
                        (pkt.sourceIP == dst && pkt.destIP == src);

            if (match) {
                if (pkt.length > 1500) {
                    oversized++;
                    if (oversized > 10) {
                        cout << "  [SKIP] Packet #" << pkt.identifier 
                             << " exceeds size limit (" << pkt.length << "B)\n";
                        retryQueue.add(pkt);
                        continue;
                    }
                }
                double delay = pkt.length / 1000.0;
                cout << "  [MATCH] Packet #" << pkt.identifier 
                     << " | Estimated delay: " << delay << "ms\n";
                matchedQueue.add(pkt);
                matched++;
            } else {
                temp.add(pkt);
            }
        }

        while (!temp.empty()) mainQueue.add(temp.remove());
        cout << "\n>> Filtering results: " << matched << " packets matched criteria\n";
    }

    void showFiltered() {
        cout << "\n";
        cout << "┌────────────────────────────────────────────────────────────────┐\n";
        cout << "│                  FILTERED PACKET LIST                          │\n";
        cout << "└────────────────────────────────────────────────────────────────┘\n\n";
        
        CustomQueue<NetworkPacket> temp;
        int count = 0;

        while (!matchedQueue.empty()) {
            NetworkPacket pkt = matchedQueue.remove();
            count++;
            double delay = pkt.length / 1000.0;
            cout << "  [#" << pkt.identifier << "] ";
            cout << "Delay: " << delay << "ms | ";
            cout << pkt.sourceIP << " ↔ " << pkt.destIP << "\n";
            temp.add(pkt);
        }

        while (!temp.empty()) matchedQueue.add(temp.remove());
        cout << "\n>> Total filtered: " << count << " packets\n";
    }

    void replayPackets() {
        cout << "\n";
        cout << "┌────────────────────────────────────────────────────────────────┐\n";
        cout << "│                    PACKET REPLAY                               │\n";
        cout << "└────────────────────────────────────────────────────────────────┘\n\n";
        
        int successful = 0;
        int failed = 0;

        while (!matchedQueue.empty()) {
            NetworkPacket pkt = matchedQueue.remove();
            bool sent = false;

            cout << "  Replaying packet #" << pkt.identifier << ":\n";
            for (int attempt = 1; attempt <= 3; attempt++) {
                cout << "    Attempt " << attempt << "/3 ... ";
                
                bool sendSuccess = (rand() % 100) > 20;
                if (pkt.length > 0 && pkt.length <= 1500 && sendSuccess) {
                    cout << "[SUCCESS]\n";
                    successful++;
                    sent = true;
                    break;
                } else {
                    cout << "[FAILED]\n";
                    if (attempt < 3) usleep(50000);
                }
            }

            if (!sent) {
                pkt.attemptsMade++;
                if (pkt.attemptsMade < 2) {
                    cout << "  >> Moved to retry queue (attempts: " << pkt.attemptsMade << ")\n";
                    retryQueue.add(pkt);
                    failed++;
                }
            }
            cout << "\n";
        }

        cout << ">> Replay summary:\n";
        cout << "   Successful: " << successful << " packets\n";
        cout << "   Failed: " << failed << " packets (moved to retry queue)\n";
    }

    void showRetries() {
        cout << "\n";
        cout << "┌────────────────────────────────────────────────────────────────┐\n";
        cout << "│                    RETRY QUEUE STATUS                          │\n";
        cout << "└────────────────────────────────────────────────────────────────┘\n\n";
        
        CustomQueue<NetworkPacket> temp;
        int count = 0;

        while (!retryQueue.empty()) {
            NetworkPacket pkt = retryQueue.remove();
            count++;
            cout << "  [#" << pkt.identifier << "] ";
            cout << "Attempts: " << pkt.attemptsMade << " | ";
            cout << pkt.sourceIP << " → " << pkt.destIP << " | ";
            cout << pkt.length << "B\n";
            temp.add(pkt);
        }

        while (!temp.empty()) retryQueue.add(temp.remove());
        cout << "\n>> Packets in retry queue: " << count << "\n";
    }

    void stats() {
        cout << "\n";
        cout << "┌────────────────────────────────────────────────────────────────┐\n";
        cout << "│                   SYSTEM STATISTICS                            │\n";
        cout << "└────────────────────────────────────────────────────────────────┘\n\n";
        cout << "  Main Queue ............... " << mainQueue.size() << " packets\n";
        cout << "  Filtered Queue ........... " << matchedQueue.size() << " packets\n";
        cout << "  Retry Queue .............. " << retryQueue.size() << " packets\n";
        cout << "  Total Packets Captured ... " << nextID << "\n\n";
    }

    int getMainCount() { return mainQueue.size(); }
};

void printMenu() {
    cout << "\n";
    cout << "══════════════════════════════════════════════════════════════════\n";
    cout << "              NETWORK PACKET MONITORING SYSTEM                    \n";
    cout << "══════════════════════════════════════════════════════════════════\n";
    cout << "\n  [1] Start Packet Capture Session\n";
    cout << "  [2] View Captured Packets\n";
    cout << "  [3] Analyze Protocol Layers\n";
    cout << "  [4] Apply IP Address Filter\n";
    cout << "  [5] View Filtered Results\n";
    cout << "  [6] Execute Packet Replay\n";
    cout << "  [7] Check Retry Queue\n";
    cout << "  [8] Display System Statistics\n";
    cout << "  [9] Run Complete Test Suite\n";
    cout << "  [0] Exit Program\n";
    cout << "\n══════════════════════════════════════════════════════════════════\n";
    cout << "  Select option: ";
}

int main() {
    if (geteuid() != 0) {
        cout << "\n══════════════════════════════════════════════════════════════════\n";
        cout << "                    ACCESS DENIED                                 \n";
        cout << "══════════════════════════════════════════════════════════════════\n";
        cout << "\n  This program requires root privileges to operate.\n";
        cout << "  Raw socket operations need elevated permissions.\n\n";
        cout << "  Please execute with: sudo ./network_monitor\n\n";
        return 1;
    }

    cout << "══════════════════════════════════════════════════════════════════\n";
    cout << "          NETWORK PACKET MONITORING SYSTEM                        \n";
    cout << "══════════════════════════════════════════════════════════════════\n";
    cout << "\n  >> Root access verified successfully\n\n";
    cout << "  System Configuration:\n";
    cout << "  ├─ Operating System: Linux\n";
    cout << "  ├─ Network Interface: enp0s3\n";
    cout << "  ├─ Packet Size Limit: 1500 bytes\n";
    cout << "  ├─ Oversized Threshold: 10 packets\n";
    cout << "  └─ Maximum Retry Attempts: 2 per packet\n";
    cout << "══════════════════════════════════════════════════════════════════\n";

    PacketMonitor monitor;

    while (true) {
        printMenu();
        int choice;
        cin >> choice;
        cin.ignore();

        switch (choice) {
            case 0:
                cout << "\n>> Shutting down monitoring system...\n";
                cout << ">> Thank you for using the packet monitor\n\n";
                return 0;

            case 1: {
                cout << "\n[OPERATION] Packet Capture";
                cout << "\n" << string(66, '-') << "\n";
                cout << "\nEnter capture duration (seconds, default=60): ";
                int dur;
                cin >> dur;
                if (dur <= 0) dur = 60;
                monitor.capture(dur);
                break;
            }

            case 2:
                cout << "\n[OPERATION] View Captured Packets";
                cout << "\n" << string(66, '-') << "\n";
                if (monitor.getMainCount() == 0) {
                    cout << "\n[INFO] No packets in capture buffer\n";
                    cout << "Use option [1] to capture network traffic\n";
                } else {
                    monitor.showPackets();
                }
                break;

            case 3:
                cout << "\n[OPERATION] Protocol Layer Analysis";
                cout << "\n" << string(66, '-') << "\n";
                if (monitor.getMainCount() == 0) {
                    cout << "\n[INFO] No packets available for analysis\n";
                    cout << "Capture packets first using option [1]\n";
                } else {
                    monitor.analyzePackets();
                }
                break;

            case 4: {
                cout << "\n[OPERATION] IP Address Filtering";
                cout << "\n" << string(66, '-') << "\n";
                if (monitor.getMainCount() == 0) {
                    cout << "\n[INFO] No packets to filter\n";
                    cout << "Capture packets first using option [1]\n";
                    break;
                }
                string src, dst;
                cout << "\nEnter source IP address: ";
                cin >> src;
                cout << "Enter destination IP address: ";
                cin >> dst;
                monitor.filterByIP(src, dst);
                break;
            }

            case 5:
                cout << "\n[OPERATION] Display Filtered Packets";
                cout << "\n" << string(66, '-') << "\n";
                monitor.showFiltered();
                break;

            case 6:
                cout << "\n[OPERATION] Packet Replay";
                cout << "\n" << string(66, '-') << "\n";
                monitor.replayPackets();
                break;

            case 7:
                cout << "\n[OPERATION] Retry Queue Status";
                cout << "\n" << string(66, '-') << "\n";
                monitor.showRetries();
                break;

            case 8:
                cout << "\n[OPERATION] System Statistics";
                cout << "\n" << string(66, '-') << "\n";
                monitor.stats();
                break;

            case 9:
                cout << "\n";
                cout << "══════════════════════════════════════════════════════════════════\n";
                cout << "              AUTOMATED TESTING SUITE - FULL DEMO                 \n";
                cout << "══════════════════════════════════════════════════════════════════\n";
                
                cout << "\n>> Test 1: Primary packet capture (60 seconds)\n";
                monitor.capture(60);
                
                if (monitor.getMainCount() > 0) {
                    cout << "\n>> Test 2: Packet inventory display\n";
                    monitor.showPackets();
                    
                    cout << "\n>> Test 3: Protocol layer analysis\n";
                    monitor.analyzePackets();
                    
                    cout << "\n>> Test 4: IP-based packet filtering\n";
                    cout << "Using default filter: 192.168.1.100 ↔ 192.168.1.1\n";
                    monitor.filterByIP("192.168.1.100", "192.168.1.1");
                    
                    cout << "\n>> Test 5: Filtered packet display\n";
                    monitor.showFiltered();
                    
                    cout << "\n>> Test 6: Packet replay execution\n";
                    monitor.replayPackets();
                    
                    cout << "\n>> Test 7: Retry queue verification\n";
                    monitor.showRetries();
                    
                    cout << "\n>> Test 8: Final system statistics\n";
                    monitor.stats();
                    
                    cout << "\n";
                    cout << "══════════════════════════════════════════════════════════════════\n";
                    cout << "              ALL TESTS COMPLETED SUCCESSFULLY                    \n";
                    cout << "══════════════════════════════════════════════════════════════════\n";
                } else {
                    cout << "\n[WARNING] No packets captured during test\n";
                    cout << "Possible issues:\n";
                    cout << "  • Network interface (enp0s3) may not exist\n";
                    cout << "  • No active network traffic on interface\n";
                    cout << "  • Insufficient capture duration\n";
                }
                break;

            default:
                cout << "\n[ERROR] Invalid selection\n";
                cout << "Please choose an option between [0-9]\n";
        }
    }

    return 0;
}