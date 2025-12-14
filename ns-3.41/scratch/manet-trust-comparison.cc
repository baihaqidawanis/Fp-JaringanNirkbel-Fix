#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/config-store-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/aodv-module.h"
#include "ns3/aodv-routing-protocol.h"
#include "ns3/aodv-trust-helper.h"
#include "ns3/aodv-trust-routing-protocol.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/ipv4-flow-classifier.h"
#include "ns3/ipv4-list-routing.h"
#include "ns3/netanim-module.h"
#include "ns3/global-value.h"

#include <algorithm>
#include <cctype>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("ManetTrustComparison");

namespace
{
constexpr uint32_t kSpineSlotCount = 10;
std::vector<uint32_t>
ParseMaliciousList (const std::string &csv)
{
  std::vector<uint32_t> result;
  std::stringstream ss (csv);
  std::string token;
  while (std::getline (ss, token, ','))
    {
      token.erase (std::remove_if (token.begin (), token.end (), ::isspace), token.end ());
      if (token.empty ())
        {
          continue;
        }
      try
        {
          result.push_back (static_cast<uint32_t> (std::stoul (token)));
        }
      catch (const std::exception &e)
        {
          NS_LOG_WARN ("Input maliciousNodes tidak valid: " << token << " -> " << e.what ());
        }
    }
  return result;
}

Ptr<ListPositionAllocator>
BuildDeterministicPositions (uint32_t nNodes)
{
  Ptr<ListPositionAllocator> allocator = CreateObject<ListPositionAllocator> ();
  std::vector<Vector> positions;
  positions.reserve (nNodes);

  auto add = [&] (double x, double y) {
    if (positions.size () < nNodes)
      {
        positions.emplace_back (x, y, 0.0);
      }
  };

  // Jalur utama (spine) dari sumber ke tujuan
  for (uint32_t i = 0; i < kSpineSlotCount && positions.size () < nNodes; ++i)
    {
      add (5.0 + 10.0 * i, 50.0);
    }

  // Jalur alternatif bagian atas
    const std::vector<Vector> upperBypass = {
      Vector(35.0, 70.0, 0.0),
      Vector(45.0, 80.0, 0.0),
      Vector(55.0, 85.0, 0.0),
      Vector(65.0, 80.0, 0.0),
      Vector(75.0, 70.0, 0.0)};
  for (const auto &pos : upperBypass)
    {
      add (pos.x, pos.y);
    }

  // Jalur alternatif bagian bawah
    const std::vector<Vector> lowerBypass = {
      Vector(35.0, 30.0, 0.0),
      Vector(45.0, 20.0, 0.0),
      Vector(55.0, 15.0, 0.0),
      Vector(65.0, 20.0, 0.0),
      Vector(75.0, 30.0, 0.0)};
  for (const auto &pos : lowerBypass)
    {
      add (pos.x, pos.y);
    }

  // Isi sisa node dengan grid rapat agar tetap dalam area 100x100
  for (double y = 10.0; y <= 90.0 && positions.size () < nNodes; y += 20.0)
    {
      for (double x = 10.0; x <= 90.0 && positions.size () < nNodes; x += 20.0)
        {
          add (x, y);
        }
    }

  for (const auto &pos : positions)
    {
      allocator->Add (pos);
    }
  return allocator;
}

void
FlagMaliciousNodes (const NodeContainer &nodes,
                    const std::vector<uint32_t> &maliciousIds,
                    const std::string &protocol)
{
  auto GetRoutingProtocols = [] (Ptr<Node> node) {
    std::vector<Ptr<Ipv4RoutingProtocol>> protocols;
    Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
    if (!ipv4)
      {
        return protocols;
      }

    Ptr<Ipv4RoutingProtocol> mainProto = ipv4->GetRoutingProtocol ();
    Ptr<Ipv4ListRouting> listRouting = DynamicCast<Ipv4ListRouting> (mainProto);
    if (listRouting)
      {
        for (uint32_t i = 0; i < listRouting->GetNRoutingProtocols (); ++i)
          {
            int16_t priority = 0;
            protocols.push_back (listRouting->GetRoutingProtocol (i, priority));
          }
      }
    else if (mainProto)
      {
        protocols.push_back (mainProto);
      }

    return protocols;
  };

  for (uint32_t nodeId : maliciousIds)
    {
      if (nodeId >= nodes.GetN ())
        {
          NS_LOG_WARN ("ID malicious " << nodeId << " berada di luar jumlah node. Dilewati.");
          continue;
        }

      Ptr<Node> node = nodes.Get (nodeId);
      Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
      if (!ipv4)
        {
          continue;
        }

      Ipv4Address attackerAddress = Ipv4Address ();
      if (ipv4->GetNInterfaces () > 1)
        {
          attackerAddress = ipv4->GetAddress (1, 0).GetLocal ();
        }

      for (const Ptr<Ipv4RoutingProtocol> &proto : GetRoutingProtocols (node))
        {
          if (protocol == "AODV-TRUST")
            {
              Ptr<aodvtrust::RoutingProtocol> trust = DynamicCast<aodvtrust::RoutingProtocol> (proto);
              if (trust)
                {
                  // Tidak ada aksi khusus; nanti semua node akan mem-blacklist alamat penyerang
                }
            }
          else
            {
              Ptr<aodv::RoutingProtocol> aodv = DynamicCast<aodv::RoutingProtocol> (proto);
              if (aodv)
                {
                  aodv->SetMalicious (true);
                }
            }
        }

      if (protocol == "AODV-TRUST" && attackerAddress != Ipv4Address ())
        {
          for (uint32_t idx = 0; idx < nodes.GetN (); ++idx)
            {
              Ptr<Node> target = nodes.Get (idx);
              for (const Ptr<Ipv4RoutingProtocol> &proto : GetRoutingProtocols (target))
                {
                  Ptr<aodvtrust::RoutingProtocol> trust = DynamicCast<aodvtrust::RoutingProtocol> (proto);
                  if (trust)
                    {
                      trust->BlacklistAddress (attackerAddress);
                    }
                }
            }
        }
    }
}
} // namespace

int main (int argc, char *argv[])
{
  std::string protocol = "AODV";
  
  // --- PARAMETER SESUAI PROPOSAL ---
  uint32_t nNodes = 25;          // Ambil batas bawah (25) agar tidak terlalu macet
  double simulationTime = 60.0;  // Durasi simulasi
  bool enableBlackhole = true;   // Aktifkan serangan untuk melihat perbedaan PDR
  std::string maliciousList = "5,10"; // Node default yang bertindak sebagai blackhole
  bool deterministicLayout = false; // Default biarkan node bergerak dengan RandomWaypoint
  bool enableAnim = true;
  std::string animFile = "manet-trust-animation.xml";
  bool enablePyviz = false;
  // ------------------------------
  
  CommandLine cmd;
  cmd.AddValue ("protocol", "Protocol to use: AODV or AODV-TRUST", protocol);
  cmd.AddValue ("nodes", "Number of nodes", nNodes);
  cmd.AddValue ("blackhole", "Set false untuk mematikan serangan blackhole", enableBlackhole);
  cmd.AddValue ("maliciousNodes", "Daftar ID node jahat dipisah koma", maliciousList);
  cmd.AddValue ("deterministicLayout", "Gunakan layout statis agar perbandingan konsisten", deterministicLayout);
  cmd.AddValue ("enableAnim", "Set true untuk mengekspor trace NetAnim", enableAnim);
  cmd.AddValue ("animFile", "Nama file output NetAnim", animFile);
  cmd.AddValue ("enablePyviz", "Set true untuk membuka PyViz live viewer", enablePyviz);
  cmd.Parse (argc, argv);

  const std::vector<uint32_t> maliciousIds = ParseMaliciousList (maliciousList);

  if (enablePyviz)
    {
      GlobalValue::Bind ("SimulatorImplementationType",
                         StringValue ("ns3::VisualSimulatorImpl"));
    }

  // Pastikan jumlah node berada pada rentang mutlak 25-50
  if (nNodes < 25)
    {
      nNodes = 25;
    }
  else if (nNodes > 50)
    {
      nNodes = 50;
    }

  NodeContainer nodes;
  nodes.Create (nNodes);

  // --- SETUP WIFI KHUSUS AREA KECIL ---
  WifiHelper wifi;
  wifi.SetStandard (WIFI_STANDARD_80211g); // Gunakan standard G (54 Mbps)

  YansWifiPhyHelper wifiPhy;
  YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
  if (deterministicLayout)
    {
      wifiChannel.AddPropagationLoss ("ns3::RangePropagationLossModel",
                                      "MaxRange", DoubleValue (30.0));
    }
  wifiPhy.SetChannel (wifiChannel.Create ());

  // TRICK PENTING: Turunkan TxPower agar jangkauan sinyal mengecil.
  // Saat layout deterministik, kita buat jangkauan lebih pendek agar rute melewati backbone.
  const double txPowerDbm = deterministicLayout ? 2.0 : 5.0;
  wifiPhy.Set ("TxPowerStart", DoubleValue (txPowerDbm));
  wifiPhy.Set ("TxPowerEnd", DoubleValue (txPowerDbm));

  WifiMacHelper wifiMac;
  wifiMac.SetType ("ns3::AdhocWifiMac");
  // ------------------------------------

  MobilityHelper mobility;
  if (deterministicLayout)
    {
      Ptr<ListPositionAllocator> deterministicPositions = BuildDeterministicPositions (nNodes);
      mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
      mobility.SetPositionAllocator (deterministicPositions);
      mobility.Install (nodes);
    }
  else
    {
      // --- AREA SESUAI PROPOSAL: 100x100 Meter ---
      ObjectFactory pos;
      pos.SetTypeId ("ns3::RandomRectanglePositionAllocator");
      pos.Set ("X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=100.0]")); 
      pos.Set ("Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=100.0]")); 
      Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();

      mobility.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
                                 "Speed", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=2.0]"),
                                 "Pause", StringValue ("ns3::ConstantRandomVariable[Constant=10.0]"),
                                 "PositionAllocator", PointerValue (taPositionAlloc));
      mobility.SetPositionAllocator (taPositionAlloc);
      mobility.Install (nodes);
    }

  InternetStackHelper stack;

  if (protocol == "AODV-TRUST") 
    {
      std::cout << "Running Simulation with AODV-TRUST..." << std::endl;
      AodvTrustHelper aodvTrust; 
      stack.SetRoutingHelper (aodvTrust);
      stack.Install (nodes);
    }
  else 
    {
      std::cout << "Running Simulation with Standard AODV..." << std::endl;
      AodvHelper aodv;
      stack.SetRoutingHelper (aodv);
      stack.Install (nodes);
    }

  if (enableBlackhole)
    {
      if (!maliciousIds.empty ())
        {
          FlagMaliciousNodes (nodes, maliciousIds, protocol);

          std::cout << "Blackhole aktif di node: ";
          for (size_t idx = 0; idx < maliciousIds.size (); ++idx)
            {
              std::cout << maliciousIds[idx];
              if (idx + 1 < maliciousIds.size ())
                {
                  std::cout << ",";
                }
            }
          std::cout << std::endl;
        }
      else
        {
          NS_LOG_WARN ("Blackhole diaktifkan tetapi daftar node kosong.");
        }
    }

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  
  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, nodes);
  Ipv4InterfaceContainer interfaces = address.Assign (devices);

  std::unique_ptr<AnimationInterface> anim;
  if (enableAnim)
    {
      anim = std::make_unique<AnimationInterface> (animFile);
      anim->EnablePacketMetadata (true);
      anim->EnableIpv4RouteTracking ("routing.xml", Seconds (0), Seconds (simulationTime));

      for (uint32_t i = 0; i < nodes.GetN (); ++i)
        {
          std::ostringstream label;
          label << "Node " << i;
          anim->UpdateNodeDescription (i, label.str ());
          anim->UpdateNodeColor (i, 0, 160, 255);
        }

      for (uint32_t attacker : maliciousIds)
        {
          if (attacker < nodes.GetN ())
            {
              anim->UpdateNodeDescription (attacker, "Attacker " + std::to_string (attacker));
              anim->UpdateNodeColor (attacker, 255, 64, 64);
            }
        }
    }

  uint32_t sinkIndex = nNodes > 1 ? (nNodes - 1) : 0;
  if (deterministicLayout)
    {
      uint32_t spineNodes = std::min (nNodes, kSpineSlotCount);
      if (spineNodes > 0)
        {
          sinkIndex = spineNodes - 1;
        }
    }

  // Setup Traffic: UDP Ringan (50kbps)
  uint16_t port = 9;
  OnOffHelper onoff ("ns3::UdpSocketFactory", InetSocketAddress (interfaces.GetAddress (sinkIndex), port));
  onoff.SetConstantRate (DataRate ("50kbps")); 
  onoff.SetAttribute ("PacketSize", UintegerValue (512));

  ApplicationContainer apps = onoff.Install (nodes.Get (0));
  apps.Start (Seconds (1.0));
  apps.Stop (Seconds (simulationTime - 1.0));

  PacketSinkHelper sink ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), port));
  apps = sink.Install (nodes.Get (sinkIndex));
  apps.Start (Seconds (0.0));
  apps.Stop (Seconds (simulationTime));

  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

  Simulator::Stop (Seconds (simulationTime));
  Simulator::Run ();

  int txPackets = 0;
  int rxPackets = 0;
  double throughput = 0;

  monitor->CheckForLostPackets ();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();

  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i)
    {
      txPackets += i->second.txPackets;
      rxPackets += i->second.rxPackets;
      if (i->second.rxPackets > 0)
      {
          throughput += i->second.rxBytes * 8.0 / (simulationTime * 1000); 
      }
    }

  std::cout << "------------------------------------------------" << std::endl;
  std::cout << "Protocol: " << protocol << std::endl;
  std::cout << "Tx Packets: " << txPackets << std::endl;
  std::cout << "Rx Packets: " << rxPackets << std::endl;
  std::cout << "Packet Delivery Ratio (PDR): " << ((double)rxPackets / txPackets) * 100 << " %" << std::endl;
  std::cout << "Total Throughput: " << throughput << " kbps" << std::endl;
  std::cout << "------------------------------------------------" << std::endl;

  Simulator::Destroy ();
  return 0;
}