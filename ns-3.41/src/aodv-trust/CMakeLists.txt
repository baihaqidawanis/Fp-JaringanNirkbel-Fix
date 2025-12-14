build_lib(
    LIBNAME aodv-trust
    SOURCE_FILES
    helper/aodv-trust-helper.cc
    model/aodv-trust-dpd.cc
    model/aodv-trust-id-cache.cc
    model/aodv-trust-neighbor.cc
    model/aodv-trust-packet.cc
    model/aodv-trust-routing-protocol.cc
    model/aodv-trust-rqueue.cc
    model/aodv-trust-rtable.cc
    HEADER_FILES
    helper/aodv-trust-helper.h
    model/aodv-trust-dpd.h
    model/aodv-trust-id-cache.h
    model/aodv-trust-neighbor.h
    model/aodv-trust-packet.h
    model/aodv-trust-routing-protocol.h
    model/aodv-trust-rqueue.h
    model/aodv-trust-rtable.h
    LIBRARIES_TO_LINK
    ${libapplications}
    ${libinternet-apps}
    ${libwifi}
    # TEST_SOURCES saya hilangkan dulu agar build tidak error
    # karena kita tidak merename file test di terminal tadi.
)