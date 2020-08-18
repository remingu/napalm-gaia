class RouteUtil:
    def __init__(self):
        pass

    @staticmethod
    def parse_aggregate_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        return _


    @staticmethod
    def parse_bgp_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        return _

    @staticmethod
    def parse_connected_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        _[destination]['protocol'] = proto
        _[destination]['outgoing_interface'] = output[5]
        _[destination]['age'] = 0
        _[destination]['next_hop'] = ''
        _[destination]['routing_table'] = 'default'
        return _


    @staticmethod
    def parse_hidden_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        return _


    @staticmethod
    def parse_kernel_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        return _


    @staticmethod
    def parse_ospf_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        return _

    @staticmethod
    def parse_suppressed_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        return _

    @staticmethod
    def parse_rip_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        return _

    @staticmethod
    def parse_static_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        _[destination]['protocol'] = proto
        _[destination]['outgoing_interface'] = output[4]
        _[destination]['age'] = output[8]
        _[destination]['next_hop'] = output[3]
        _[destination]['routing_table'] = 'default'
        return _

    @staticmethod
    def parse_unreachable_route(proto: str, destination: str, output: list) -> dict:
        _ = {destination: {}}
        return _

    @staticmethod
    def parse_none_route(proto: str, destination: str) -> dict:
        _ = {destination: {}}
        _[destination]['protocol'] = 'None'
        _[destination]['outgoing_interface'] = 'None'
        _[destination]['age'] = 0
        _[destination]['next_hop'] = ''
        _[destination]['routing_table'] = 'default'
        return _