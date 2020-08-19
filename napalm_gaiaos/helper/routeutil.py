class RouteUtil:
    @staticmethod
    def parse_aggregate_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        _[destination]['protocol'] = proto
        _[destination]['outgoing_interface'] = output[4]
        _[destination]['age'] = output[8]
        _[destination]['next_hop'] = output[3]
        _[destination]['routing_table'] = 'default'
        _[destination]['protocol_attributes']: {}
        _[destination]['selected_next_hop'] = True
        _[destination]['inactive_reason'] = ''
        _[destination]['preference'] = 0
        _[destination]['current_active'] = True
        _[destination]['last_active'] = True
        return _

    @staticmethod
    def parse_bgp_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        bgp_rtypes = {'D': 'Default'}
        for rtype in bgp_rtypes:
            if rtype == output[1]:
                proto = proto + '-' + bgp_rtypes[rtype]
                _[destination]['protocol'] = proto
                _[destination]['outgoing_interface'] = output[5]
                _[destination]['age'] = output[9]
                _[destination]['next_hop'] = output[4]
                _[destination]['routing_table'] = 'default'
                _[destination]['protocol_attributes']: {}
                _[destination]['selected_next_hop'] = True
                _[destination]['inactive_reason'] = ''
                _[destination]['preference'] = 0
                _[destination]['current_active'] = True
                _[destination]['last_active'] = True
            else:
                _[destination]['protocol'] = proto
                _[destination]['outgoing_interface'] = output[4]
                _[destination]['age'] = output[8]
                _[destination]['next_hop'] = output[3]
                _[destination]['routing_table'] = 'default'
                _[destination]['protocol_attributes']: {}
                _[destination]['selected_next_hop'] = True
                _[destination]['inactive_reason'] = ''
                _[destination]['preference'] = 0
                _[destination]['current_active'] = True
                _[destination]['last_active'] = True
        return _

    @staticmethod
    def parse_connected_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        _[destination]['protocol'] = proto
        _[destination]['outgoing_interface'] = output[5]
        _[destination]['age'] = 0
        _[destination]['next_hop'] = ''
        _[destination]['routing_table'] = 'default'
        _[destination]['protocol_attributes']: {}
        _[destination]['selected_next_hop'] = False
        _[destination]['inactive_reason'] = ''
        _[destination]['preference'] = 0
        _[destination]['current_active'] = True
        _[destination]['last_active'] = True
        return _

    @staticmethod
    def parse_hidden_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        _[destination]['protocol'] = proto
        _[destination]['outgoing_interface'] = output[4]
        _[destination]['age'] = output[8]
        _[destination]['next_hop'] = output[3]
        _[destination]['routing_table'] = 'default'
        _[destination]['protocol_attributes']: {}
        _[destination]['selected_next_hop'] = False
        _[destination]['inactive_reason'] = ''
        _[destination]['preference'] = 0
        _[destination]['current_active'] = False
        _[destination]['last_active'] = False
        return _

    @staticmethod
    def parse_inactive_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        _[destination]['protocol'] = proto
        _[destination]['outgoing_interface'] = output[4]
        _[destination]['age'] = output[8]
        _[destination]['next_hop'] = output[3]
        _[destination]['routing_table'] = 'default'
        _[destination]['protocol_attributes']: {}
        _[destination]['selected_next_hop'] = False
        _[destination]['inactive_reason'] = ''
        _[destination]['preference'] = 0
        _[destination]['current_active'] = False
        _[destination]['last_active'] = False
        return _

    @staticmethod
    def parse_kernel_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        _[destination]['protocol'] = proto
        _[destination]['outgoing_interface'] = output[4]
        _[destination]['age'] = output[8]
        _[destination]['next_hop'] = output[3]
        _[destination]['routing_table'] = 'default'
        _[destination]['protocol_attributes']: {}
        _[destination]['selected_next_hop'] = False
        _[destination]['inactive_reason'] = ''
        _[destination]['preference'] = 0
        _[destination]['current_active'] = False
        _[destination]['last_active'] = False
        return _

    @staticmethod
    def parse_ospf_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        ospf_rtypes = {'E': 'External', 'IA': 'InterArea', 'N' : 'NSSA'}
        for rtype in ospf_rtypes:
            if rtype == output[1]:
                proto = proto + '-' + ospf_rtypes[rtype]
                _[destination]['protocol'] = proto
                _[destination]['outgoing_interface'] = output[5]
                _[destination]['age'] = output[9]
                _[destination]['next_hop'] = output[4]
                _[destination]['routing_table'] = 'default'
                _[destination]['protocol_attributes']: {}
                _[destination]['selected_next_hop'] = True
                _[destination]['inactive_reason'] = ''
                _[destination]['preference'] = 0
                _[destination]['current_active'] = True
                _[destination]['last_active'] = True
            else:
                _[destination]['protocol'] = proto
                _[destination]['outgoing_interface'] = output[4]
                _[destination]['age'] = output[8]
                _[destination]['next_hop'] = output[3]
                _[destination]['routing_table'] = 'default'
                _[destination]['protocol_attributes']: {}
                _[destination]['selected_next_hop'] = True
                _[destination]['inactive_reason'] = ''
                _[destination]['preference'] = 0
                _[destination]['current_active'] = True
                _[destination]['last_active'] = True
        return _

    @staticmethod
    def parse_suppressed_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        _[destination]['protocol'] = proto
        _[destination]['outgoing_interface'] = output[4]
        _[destination]['age'] = output[8]
        _[destination]['next_hop'] = output[3]
        _[destination]['routing_table'] = 'default'
        _[destination]['protocol_attributes']: {}
        _[destination]['selected_next_hop'] = False
        _[destination]['inactive_reason'] = ''
        _[destination]['preference'] = 0
        _[destination]['current_active'] = False
        _[destination]['last_active'] = False
        return _

    @staticmethod
    def parse_rip_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        _[destination]['protocol'] = proto
        _[destination]['outgoing_interface'] = output[4]
        _[destination]['age'] = output[8]
        _[destination]['next_hop'] = output[3]
        _[destination]['routing_table'] = 'default'
        _[destination]['protocol_attributes']: {}
        _[destination]['selected_next_hop'] = True
        _[destination]['inactive_reason'] = ''
        _[destination]['preference'] = 0
        _[destination]['current_active'] = True
        _[destination]['last_active'] = True
        return _

    @staticmethod
    def parse_static_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        _[destination]['protocol'] = proto
        _[destination]['outgoing_interface'] = output[4]
        _[destination]['age'] = output[8]
        _[destination]['next_hop'] = output[3]
        _[destination]['routing_table'] = 'default'
        _[destination]['protocol_attributes']: {}
        _[destination]['selected_next_hop'] = True
        _[destination]['inactive_reason'] = ''
        _[destination]['preference'] = 0
        _[destination]['current_active'] = True
        _[destination]['last_active'] = True
        return _

    @staticmethod
    def parse_unreachable_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        _[destination]['protocol'] = 'None'
        _[destination]['outgoing_interface'] = 'None'
        _[destination]['age'] = 0
        _[destination]['next_hop'] = ''
        _[destination]['routing_table'] = 'default'
        _[destination]['protocol_attributes']: {}
        _[destination]['selected_next_hop'] = True
        _[destination]['inactive_reason'] = ''
        _[destination]['preference'] = 0
        _[destination]['current_active'] = True
        _[destination]['last_active'] = True
        return _

    @staticmethod
    def parse_none_route(proto: str, destination: str) -> dict:
        _ = {destination: {}}
        _[destination]['protocol'] = 'None'
        _[destination]['outgoing_interface'] = 'None'
        _[destination]['age'] = 0
        _[destination]['next_hop'] = ''
        _[destination]['routing_table'] = 'default'
        _[destination]['protocol_attributes']: {}
        _[destination]['selected_next_hop'] = False
        _[destination]['inactive_reason'] = ''
        _[destination]['preference'] = 0
        _[destination]['current_active'] = False
        _[destination]['last_active'] = False
        return _
