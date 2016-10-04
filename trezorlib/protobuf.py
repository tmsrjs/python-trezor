#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Implements the Google's protobuf encoding.
#
# Fork of Micropython-optimized protobuf library used in TREZOR Core (Python 3.5+)
# use minimal subset of protobuf features required by TREZOR.
#
# Compatible with Python2/3
# Forked from https://github.com/trezor/trezor-core/blob/455a4361232d7deeb617f05981f1bd28ec80c13d/src/lib/protobuf/protobuf.py
#
# Satoshilabs (c) 2016
# eigenein (c) 2011 (http://eigenein.me/protobuf/)

from io import BytesIO

# Types. -----------------------------------------------------------------


class UVarintType:
    # Represents an unsigned Varint type.
    WIRE_TYPE = 0

    @staticmethod
    def dump(fp, value):
        shifted_value = True
        while shifted_value:
            shifted_value = value >> 7
            d = (value & 0x7F) | (0x80 if shifted_value != 0 else 0x00)
            fp.write(bytearray((d,)))
            value = shifted_value

    @staticmethod
    def load(fp):
        value, shift, quantum = 0, 0, 0x80
        while (quantum & 0x80) == 0x80:
            quantum = ord(fp.read(1))
            value, shift = value + ((quantum & 0x7F) << shift), shift + 7
        return value


class BoolType:
    # Represents a boolean type.
    # Encodes True as UVarint 1, and False as UVarint 0.
    WIRE_TYPE = 0

    @staticmethod
    def dump(fp, value):
        fp.write(bytearray((0x01 if value else 0x00,)))

    @staticmethod
    def load(fp):
        return UVarintType.load(fp) != 0


class BytesType:
    # Represents a raw bytes type.
    WIRE_TYPE = 2

    @staticmethod
    def dump(fp, value):
        UVarintType.dump(fp, len(value))
        fp.write(value)

    @staticmethod
    def load(fp):
        return fp.read(UVarintType.load(fp))


class UnicodeType:
    # Represents an unicode string type.
    WIRE_TYPE = 2

    @staticmethod
    def dump(fp, value):
        BytesType.dump(fp, bytearray(value, 'utf-8'))

    @staticmethod
    def load(fp):
        return BytesType.load(fp).decode('utf-8', 'strict')


# Messages. --------------------------------------------------------------

FLAG_SIMPLE = 0
FLAG_REQUIRED = 1
FLAG_REQUIRED_MASK = 1
FLAG_SINGLE = 0
FLAG_REPEATED = 2
FLAG_REPEATED_MASK = 6


class EofWrapper:
    # Wraps a stream to raise EOFError instead of just returning of ''.

    def __init__(self, fp, limit=None):
        self.__fp = fp
        self.__limit = limit

    def read(self, size=None):
        # Reads a string. Raises EOFError on end of stream.
        if self.__limit is not None:
            size = min(size, self.__limit)
            self.__limit -= size
        s = self.__fp.read(size)
        if len(s) == 0:
            raise EOFError()
        return s


# Packs a tag and a wire_type into single int according to the protobuf spec.
_pack_key = lambda tag, wire_type: (tag << 3) | wire_type
# Unpacks a key into a tag and a wire_type according to the protobuf spec.
_unpack_key = lambda key: (key >> 3, key & 7)


class MessageType:
    # Represents a message type.

    def __init__(self, name=None):
        # Creates a new message type.
        self.__tags_to_types = {}  # Maps a tag to a type instance.
        self.__tags_to_names = {}  # Maps a tag to a given field name.
        self.__defaults = {}  # Maps a tag to its default value.
        self.__flags = {}  # Maps a tag to FLAG_
        self._name = name

    def add_field(self, tag, name, field_type, flags=FLAG_SIMPLE, default=None):
        # Adds a field to the message type.
        if tag in self.__tags_to_names or tag in self.__tags_to_types:
            raise ValueError('The tag %s is already used.' % tag)
        if default != None:
            self.__defaults[tag] = default
        self.__tags_to_names[tag] = name
        self.__tags_to_types[tag] = field_type
        self.__flags[tag] = flags
        return self  # Allow add_field chaining.

    def __call__(self, **fields):
        # Creates an instance of this message type.
        return Message(self, **fields)

    def __has_flag(self, tag, flag, mask):
        # Checks whether the field with the specified tag has the specified
        # flag.
        return (self.__flags[tag] & mask) == flag

    def get_default(self, name):
        print("GETTING DEFAULT FOR ", name)
        if name not in self.__tags_to_names.values():
            raise Exception("Unknown field %s.%s" % (self._name, name))

        tag = [k for (k, v) in self.__tags_to_names.iteritems() if v == name][0]
        return self.__defaults.get(tag, None)

    def dump(self, fp, value):
        if self != value.message_type:
            raise TypeError("Incompatible type")
        for tag, field_type in iter(self.__tags_to_types.items()):
            if self.__tags_to_names[tag] in value.__dict__:
                if self.__has_flag(tag, FLAG_SINGLE, FLAG_REPEATED_MASK):
                    # Single value.
                    UVarintType.dump(fp, _pack_key(tag, field_type.WIRE_TYPE))
                    field_type.dump(fp, getattr(
                        value, self.__tags_to_names[tag]))
                elif self.__has_flag(tag, FLAG_REPEATED, FLAG_REPEATED_MASK):
                    # Repeated value.
                    key = _pack_key(tag, field_type.WIRE_TYPE)
                    # Put it together sequently.
                    for single_value in getattr(value, self.__tags_to_names[tag]):
                        UVarintType.dump(fp, key)
                        field_type.dump(fp, single_value)
            elif self.__has_flag(tag, FLAG_REQUIRED, FLAG_REQUIRED_MASK):
                raise ValueError(
                    'The field with the tag %s is required but a value is missing.' % tag)

    def load(self, fp):
        fp = EofWrapper(fp)
        message = self.__call__()
        while True:
            try:
                tag, wire_type = _unpack_key(UVarintType.load(fp))

                if tag in self.__tags_to_types:
                    field_type = self.__tags_to_types[tag]
                    field_name = self.__tags_to_names[tag]
                    if wire_type != field_type.WIRE_TYPE:
                        raise TypeError(
                            'Value of tag %s has incorrect wiretype %s, %s expected.' %
                            (tag, wire_type, field_type.WIRE_TYPE))
                    if self.__has_flag(tag, FLAG_SINGLE, FLAG_REPEATED_MASK):
                        # Single value.
                        setattr(message, field_name, field_type.load(fp))
                    elif self.__has_flag(tag, FLAG_REPEATED, FLAG_REPEATED_MASK):
                        # Repeated value.
                        if not field_name in message.__dict__:
                            setattr(message, field_name, [])
                        getattr(message, field_name).append(
                            field_type.load(fp))
                else:
                    # Skip this field.

                    # This used to correctly determine the length of unknown
                    # tags when loading a message.
                    {0: UVarintType, 2: BytesType}[wire_type].load(fp)

            except EOFError:
                for tag, name in iter(self.__tags_to_names.items()):
                    # Fill in default value if value not set
                    if name not in message.__dict__ and tag in self.__defaults:
                        setattr(message, name, self.__defaults[tag])

                    # Check if all required fields are present.
                    if self.__has_flag(tag, FLAG_REQUIRED, FLAG_REQUIRED_MASK) and not name in message.__dict__:
                        if self.__has_flag(tag, FLAG_REPEATED, FLAG_REPEATED_MASK):
                            # Empty list (no values was in input stream). But
                            # required field.
                            setattr(message, name, [])
                        else:
                            raise ValueError(
                                'The field %s (\'%s\') is required but missing.' % (tag, name))
                return message

    def dumps(self, value):
        fp = BytesIO()
        self.dump(fp, value)
        return fp.getvalue()

    def loads(self, buf):
        fp = BytesIO(buf)
        return self.load(fp)

    def __repr__(self):
        return '<MessageType: %s>' % self._name


class Message:
    # Represents a message instance.

    def __init__(self, message_type, **fields):
        # Initializes a new instance of the specified message type.
        self.message_type = message_type
        # In micropython, we cannot use self.__dict__.update(fields),
        # iterate fields and assign them directly.
        for key in fields:
            setattr(self, key, fields[key])

    def dump(self, fp):
        # Dumps the message into a write-like object.
        return self.message_type.dump(fp, self)

    def dumps(self):
        # Dumps the message into bytes
        return self.message_type.dumps(self)

    def __repr__(self):
        values = self.__dict__
        values = {k: values[k] for k in values if k != 'message_type'}
        return '<%s: %s>' % (self.message_type._name, values)

    def __getattr__(self, name):
        if name.startswith('_'):
            return object.__getattr__(self, name)

        if name in self.__dict__:
            return self.__dict__[name]

        return self.message_type.get_default(name)

    def __eq__(self, other):
        if isinstance(other, MessageType):
            # If we have the same message type as the other object
            return self.message_type == other

        elif isinstance(other, Message):
            if self.message_type != other.message_type:
                # Those are two completely different types
                return False

            # If we compare two initialized messages, let's compare its content
            return self.__dict__ == other.__dict__
        elif other is None:
            return False

        print(self, other, isinstance(other, MessageType))
        raise Exception("Such equality test is not implemented")

# Embedded message. ------------------------------------------------------

class EmbeddedMessage:
    # Represents an embedded message type.

    WIRE_TYPE = 2

    def __init__(self, message_type):
        # Initializes a new instance. The argument is an underlying message
        # type.
        self.message_type = message_type

    def __call__(self):
        # Creates a message of the underlying message type.
        return self.message_type()

    def dump(self, fp, value):
        BytesType.dump(fp, self.message_type.dumps(value))

    def load(self, fp):
        return self.message_type.load(EofWrapper(fp, UVarintType.load(fp)))

if __name__ == '__main__':
    CoinType = MessageType('CoinType')
    CoinType.add_field(1, 'coin_name', UnicodeType)
    CoinType.add_field(2, 'coin_shortcut', UnicodeType)
    CoinType.add_field(3, 'address_type', UVarintType, default=0)
    CoinType.add_field(4, 'maxfee_kb', UVarintType)
    CoinType.add_field(5, 'address_type_p2sh', UVarintType, default=5)
    CoinType.add_field(6, 'address_type_p2wpkh', UVarintType, default=6)
    CoinType.add_field(7, 'address_type_p2wsh', UVarintType, default=10)

    Features = MessageType('Features')
    Features.add_field(1, 'vendor', UnicodeType)
    Features.add_field(2, 'major_version', UVarintType)
    Features.add_field(3, 'minor_version', UVarintType)
    Features.add_field(4, 'patch_version', UVarintType)
    Features.add_field(5, 'bootloader_mode', BoolType)
    Features.add_field(6, 'device_id', UnicodeType)
    Features.add_field(7, 'pin_protection', BoolType)
    Features.add_field(8, 'passphrase_protection', BoolType)
    Features.add_field(9, 'language', UnicodeType)
    Features.add_field(10, 'label', UnicodeType)
    Features.add_field(11, 'coins', EmbeddedMessage(CoinType), flags=FLAG_REPEATED)
    Features.add_field(12, 'initialized', BoolType)
    Features.add_field(13, 'revision', BytesType)
    Features.add_field(14, 'bootloader_hash', BytesType)
    Features.add_field(15, 'imported', BoolType)
    Features.add_field(16, 'pin_cached', BoolType)
    Features.add_field(17, 'passphrase_cached', BoolType)

    # Sample: hex-encoded Features message
    feat = '0a11626974636f696e7472657a6f722e636f6d100218002000320844454144424545463801400052094d79205452455a4f5260006a086465616462656566720864656164626565667800c2800100c2880100'
    import binascii
    m = Features.loads(binascii.unhexlify(feat))
    print(m)

    # Example of custom-defined message type
    t = MessageType('MyCustomType')
    t.add_field(1, 'string_field', UnicodeType, default='Default value')
    t.add_field(2, 'bool_field', BoolType)
    t.add_field(3, 'int_field', UVarintType)
    m = t()
    print(m.string_field) # Prints default value

    m.string_field = u'Lorem ipsum'
    m.bool_field = True
    m.int_field = 42
    data = m.dumps()
    print(m)
    print(binascii.hexlify(data))
    print(t.loads(data))
