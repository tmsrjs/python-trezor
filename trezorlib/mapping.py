try:
    from messages import MessageType
except ImportError:
    raise Exception("Please run ./build_pb2.sh to generate message definitions.")

import protobuf

map_type_to_class = {}
map_class_to_type = {}
map_name_to_class = {}

def build_map():
    '''For internal usage only, scans built-in messages and register them to client.'''
    for msg_name in MessageType.__dict__.keys():
        if msg_name.startswith('_'):
            continue
        mod = __import__('trezorlib.messages', globals(), locals(), [msg_name,])
        msg_class = getattr(mod, msg_name).__dict__[msg_name]
        register_type(msg_class)

def get_type(msg):
    '''Detect type of given protobuf message'''
    return map_class_to_type[msg.message_type]

def get_class(t):
    '''Return class of given type (must be registered with register_type()).'''
    if isinstance(t, int):
        return map_type_to_class[t]
    if isinstance(t, protobuf.MessageType):
        return t
    return map_name_to_class[t]

def register_type(msg_class, wire_type=None):
    '''Public method to register custom message type for later handling in the client.'''
    if wire_type == None:
        wire_type = MessageType.__dict__[msg_class._name]

    if wire_type in map_type_to_class:
        raise Exception("Wire type %d already handled by class %s" % (wire_type, str(get_class(wire_type))))
    map_type_to_class[msg_class.wire_type] = msg_class
    map_class_to_type[msg_class] = msg_class.wire_type
    map_name_to_class[msg_class._name] = msg_class

build_map()