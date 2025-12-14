/*
 * Copyright (c) 2009 IITP RAS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Elena Buchatskaia <borovkovaes@iitp.ru>
 * Pavel Boyko <boyko@iitp.ru>
 */
#include "aodv-trust-helper.h"

#include "ns3/aodv-trust-routing-protocol.h"
#include "ns3/ipv4-list-routing.h"
#include "ns3/names.h"
#include "ns3/node-list.h"
#include "ns3/ptr.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/udp-l4-protocol.h"

namespace ns3
{

AodvTrustHelper::AodvTrustHelper()
    : Ipv4RoutingHelper()
{
    m_agentFactory.SetTypeId("ns3::aodvtrust::RoutingProtocol");
}

AodvTrustHelper*
AodvTrustHelper::Copy() const
{
    return new AodvTrustHelper(*this);
}

Ptr<Ipv4RoutingProtocol>
AodvTrustHelper::Create(Ptr<Node> node) const
{
    Ptr<aodvtrust::RoutingProtocol> agent = m_agentFactory.Create<aodvtrust::RoutingProtocol>();
    node->AggregateObject(agent);
    return agent;
}

void
AodvTrustHelper::Set(std::string name, const AttributeValue& value)
{
    m_agentFactory.Set(name, value);
}

int64_t
AodvTrustHelper::AssignStreams(NodeContainer c, int64_t stream)
{
    int64_t currentStream = stream;
    Ptr<Node> node;
    for (NodeContainer::Iterator i = c.Begin(); i != c.End(); ++i)
    {
        node = (*i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        NS_ASSERT_MSG(ipv4, "Ipv4 not installed on node");
        Ptr<Ipv4RoutingProtocol> proto = ipv4->GetRoutingProtocol();
        Ptr<aodvtrust::RoutingProtocol> aodvTrust = DynamicCast<aodvtrust::RoutingProtocol>(proto);
        if (aodvTrust)
        {
            currentStream += aodvTrust->AssignStreams(currentStream);
            continue;
        }
        // otherwise, check if it is a list
        Ptr<Ipv4ListRouting> listRouting = DynamicCast<Ipv4ListRouting>(proto);
        if (listRouting)
        {
            int16_t priority;
            Ptr<Ipv4RoutingProtocol> listProto;
            Ptr<aodvtrust::RoutingProtocol> listAodvTrust;
            for (uint32_t i = 0; i < listRouting->GetNRoutingProtocols(); i++)
            {
                listProto = listRouting->GetRoutingProtocol(i, priority);
                listAodvTrust = DynamicCast<aodvtrust::RoutingProtocol>(listProto);
                if (listAodvTrust)
                {
                    currentStream += listAodvTrust->AssignStreams(currentStream);
                    break;
                }
            }
        }
    }
    return (currentStream - stream);
}

} // namespace ns3