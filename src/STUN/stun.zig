pub const Cookie: u32 = 0x2112A442;
pub const FingerprintOffset: u32 = 0x5354554E;

pub const MessageKind = enum(u16) {
    BindingRequest = 0x0001,
    BindingSuccessResponse = 0x00101,
    BindingErrorResponse = 0x00111,
};

pub const STUNMessageHeader = struct {
    length: u16,
    type: MessageKind,

    transaction_id: [12]u8,
};

pub const AttributeKind = enum(u16) {
    Username = 0x0006,
    MessageIntegrity = 0x0008,
    XOrMappedAddress = 0x0020,
    Priority = 0x0024,
    UseCandidate = 0x0025,
    IceControlled = 0x8029,
    IceControlling = 0x802A,
    FingerPrint = 0x8028,
};

//  /// <summary>
//  ///     A span-first STUN (RFC 5389/8445) message codec: header plus the small set of
//  ///     attributes the ICE connectivity checks in this stack need. MESSAGE-INTEGRITY and
//  ///     FINGERPRINT are appended on top of <see cref="WriteTo" />.
//  /// </summary>
//  public class StunMessage
//  {
//   public const uint MagicCookie = 0x2112A442;
//   public const int HeaderSize = 20;

//   /// <summary>
//   ///     Largest message this stack emits. Callers size their stackalloc/lease with it.
//   /// </summary>
//   public const int MaxSize = 548;

//   private const ushort AttributeUsername = 0x0006;
//   private const ushort AttributeMessageIntegrity = 0x0008;
//   private const ushort AttributeXorMappedAddress = 0x0020;
//   private const ushort AttributePriority = 0x0024;
//   private const ushort AttributeUseCandidate = 0x0025;
//   private const ushort AttributeIceControlled = 0x8029;
//   private const ushort AttributeIceControlling = 0x802A;
//   private const ushort AttributeFingerprint = 0x8028;

//   private const byte FamilyIPv4 = 0x01;
//   private const byte FamilyIPv6 = 0x02;

//   private const int MessageIntegritySize = 20;
//   private const int FingerprintSize = 4;
//   private const uint FingerprintXor = 0x5354554E;

//   public StunMessageType Type { get; set; }
//   public byte[] TransactionId { get; set; }
//   public string Username { get; set; }
//   public IPEndPoint XorMappedAddress { get; set; }
//   public uint? Priority { get; set; }
//   public bool UseCandidate { get; set; }
//   public ulong? IceControlling { get; set; }
//   public ulong? IceControlled { get; set; }

//   /// <summary>
//   ///     Cheap pre-filter for demultiplexing STUN from other traffic on the same socket
//   ///     (e.g. DTLS): first byte below 4, at least a full header, and the magic cookie
//   ///     in place. Does not validate the rest of the message.
//   /// </summary>
//   public static bool LooksLikeStun(ReadOnlySpan<byte> packet)
//   {
//    return packet.Length >= HeaderSize
//     && packet[0] < 4
//     && BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(4)) == MagicCookie;
//   }

//   public static StunMessage Parse(ReadOnlySpan<byte> packet)
//   {
//    if (!LooksLikeStun(packet)) throw new FormatException("Not a STUN message");

//    int attributesLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2));
//    if (HeaderSize + attributesLength > packet.Length) throw new FormatException("STUN message length exceeds packet");

//    var message = new StunMessage
//    {
//     Type = (StunMessageType) BinaryPrimitives.ReadUInt16BigEndian(packet),
//     TransactionId = packet.Slice(8, 12).ToArray()
//    };

//    int offset = HeaderSize;
//    int end = HeaderSize + attributesLength;
//    while (offset + 4 <= end)
//    {
//     ushort attributeType = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset));
//     ushort attributeLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset + 2));
//     int valueOffset = offset + 4;
//     if (valueOffset + attributeLength > end) throw new FormatException("STUN attribute exceeds message");

//     ReadOnlySpan<byte> value = packet.Slice(valueOffset, attributeLength);

//     switch (attributeType)
//     {
//      case AttributeUsername:
//       message.Username = Encoding.UTF8.GetString(value);
//       break;

//      case AttributePriority:
//       if (attributeLength >= 4) message.Priority = BinaryPrimitives.ReadUInt32BigEndian(value);
//       break;

//      case AttributeUseCandidate:
//       message.UseCandidate = true;
//       break;

//      case AttributeIceControlling:
//       if (attributeLength >= 8) message.IceControlling = BinaryPrimitives.ReadUInt64BigEndian(value);
//       break;

//      case AttributeIceControlled:
//       if (attributeLength >= 8) message.IceControlled = BinaryPrimitives.ReadUInt64BigEndian(value);
//       break;

//      case AttributeXorMappedAddress:
//       message.XorMappedAddress = ParseXorMappedAddress(value, message.TransactionId);
//       break;

//      default:
//       // Unknown attribute. Comprehension-optional (type >= 0x8000) attributes are
//       // meant to be skipped; unknown comprehension-required attributes below 0x8000
//       // also just skip here, we are not a general purpose STUN server.
//       break;
//     }

//     int padded = (attributeLength + 3) & ~3;
//     offset = valueOffset + padded;
//    }

//    return message;
//   }

//   /// <summary>
//   ///     Writes the header and attributes with no MESSAGE-INTEGRITY or FINGERPRINT.
//   ///     Equivalent to <see cref="WriteTo(Span{byte}, ReadOnlySpan{byte}, bool)" /> with an
//   ///     empty key and no fingerprint.
//   /// </summary>
//   public int WriteTo(Span<byte> destination)
//   {
//    return WriteTo(destination, ReadOnlySpan<byte>.Empty, false);
//   }

//   /// <summary>
//   ///     Writes the header and attributes in a fixed order: USERNAME, PRIORITY,
//   ///     USE-CANDIDATE, ICE-CONTROLLING, ICE-CONTROLLED, XOR-MAPPED-ADDRESS, then
//   ///     optionally MESSAGE-INTEGRITY (HMAC-SHA1 keyed with <paramref name="integrityKey" />,
//   ///     RFC 5389 section 15.4) and, independently, FINGERPRINT (CRC-32 XOR'd with
//   ///     0x5354554e, section 15.5). Each trailer patches the header length field to cover
//   ///     itself before it is hashed, since both are computed over the bytes that precede
//   ///     them, including that length. An empty <paramref name="integrityKey" /> skips
//   ///     MESSAGE-INTEGRITY; <paramref name="addFingerprint" /> controls FINGERPRINT on its
//   ///     own, matching FINGERPRINT's independence from the credential mechanism.
//   /// </summary>
//   public int WriteTo(Span<byte> destination, ReadOnlySpan<byte> integrityKey, bool addFingerprint)
//   {
//    BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort) Type);
//    BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4), MagicCookie);
//    TransactionId.AsSpan().CopyTo(destination.Slice(8, 12));

//    int offset = HeaderSize;

//    if (Username != null)
//    {
//     int valueLength = Encoding.UTF8.GetByteCount(Username);
//     offset += WriteAttributeHeader(destination.Slice(offset), AttributeUsername, (ushort) valueLength);
//     Encoding.UTF8.GetBytes(Username.AsSpan(), destination.Slice(offset, valueLength));

//     int padding = (4 - valueLength % 4) % 4;
//     if (padding > 0) destination.Slice(offset + valueLength, padding).Clear();
//     offset += valueLength + padding;
//    }

//    if (Priority.HasValue)
//    {
//     offset += WriteAttributeHeader(destination.Slice(offset), AttributePriority, 4);
//     BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset), Priority.Value);
//     offset += 4;
//    }

//    if (UseCandidate)
//    {
//     offset += WriteAttributeHeader(destination.Slice(offset), AttributeUseCandidate, 0);
//    }

//    if (IceControlling.HasValue)
//    {
//     offset += WriteAttributeHeader(destination.Slice(offset), AttributeIceControlling, 8);
//     BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(offset), IceControlling.Value);
//     offset += 8;
//    }

//    if (IceControlled.HasValue)
//    {
//     offset += WriteAttributeHeader(destination.Slice(offset), AttributeIceControlled, 8);
//     BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(offset), IceControlled.Value);
//     offset += 8;
//    }

//    if (XorMappedAddress != null)
//    {
//     offset += WriteXorMappedAddress(destination.Slice(offset), XorMappedAddress, TransactionId);
//    }

//    BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2), (ushort) (offset - HeaderSize));

//    if (!integrityKey.IsEmpty)
//    {
//     // The HMAC covers the message up to but not including the MESSAGE-INTEGRITY
//     // attribute itself (RFC 5389 section 15.4): neither its TLV header nor its
//     // value, so the prefix length used here is "offset" as it stands right now.
//     int integrityOffset = offset;
//     int lengthThroughIntegrity = integrityOffset - HeaderSize + 4 + MessageIntegritySize;
//     BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2), (ushort) lengthThroughIntegrity);

//     WriteAttributeHeader(destination.Slice(integrityOffset), AttributeMessageIntegrity, MessageIntegritySize);
//     HMACSHA1.HashData(integrityKey, destination.Slice(0, integrityOffset), destination.Slice(integrityOffset + 4, MessageIntegritySize));
//     offset = integrityOffset + 4 + MessageIntegritySize;
//    }

//    if (addFingerprint)
//    {
//     // FINGERPRINT (section 15.5) is independent of the credential mechanism, so
//     // it is added whenever requested, whether or not MESSAGE-INTEGRITY is present.
//     // The CRC covers everything before the FINGERPRINT attribute, header and
//     // value both excluded, same rule as MESSAGE-INTEGRITY above.
//     int fingerprintOffset = offset;
//     int lengthThroughFingerprint = fingerprintOffset - HeaderSize + 4 + FingerprintSize;
//     BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2), (ushort) lengthThroughFingerprint);

//     WriteAttributeHeader(destination.Slice(fingerprintOffset), AttributeFingerprint, FingerprintSize);
//     uint crc = StunCrc32.Compute(destination.Slice(0, fingerprintOffset)) ^ FingerprintXor;
//     BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(fingerprintOffset + 4), crc);
//     offset = fingerprintOffset + 4 + FingerprintSize;
//    }

//    return offset;
//   }

//   /// <summary>
//   ///     Recomputes MESSAGE-INTEGRITY over <paramref name="packet" /> and compares it to the
//   ///     attribute's value in constant time. Walks the attribute TLVs to find MESSAGE-INTEGRITY
//   ///     (it may be followed by FINGERPRINT, which is not covered by the HMAC), copies the
//   ///     covered prefix into a stack buffer, patches its length field to cover through
//   ///     MESSAGE-INTEGRITY per RFC 5389 section 15.4, and recomputes the HMAC over that copy.
//   /// </summary>
//   public static bool VerifyIntegrity(ReadOnlySpan<byte> packet, ReadOnlySpan<byte> integrityKey)
//   {
//    if (!LooksLikeStun(packet)) return false;

//    int attributesLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2));
//    int end = HeaderSize + attributesLength;
//    if (end > packet.Length) return false;

//    int offset = HeaderSize;
//    int integrityAttributeOffset = -1;
//    while (offset + 4 <= end)
//    {
//     ushort attributeType = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset));
//     ushort attributeLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset + 2));
//     int valueOffset = offset + 4;
//     if (valueOffset + attributeLength > end) return false;

//     if (attributeType == AttributeMessageIntegrity)
//     {
//      integrityAttributeOffset = offset;
//      break;
//     }

//     int padded = (attributeLength + 3) & ~3;
//     offset = valueOffset + padded;
//    }

//    if (integrityAttributeOffset < 0) return false;
//    if (integrityAttributeOffset > MaxSize) return false;

//    ushort integrityValueLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(integrityAttributeOffset + 2));
//    if (integrityValueLength != MessageIntegritySize) return false;

//    int integrityValueOffset = integrityAttributeOffset + 4;
//    if (integrityValueOffset + MessageIntegritySize > packet.Length) return false;

//    ReadOnlySpan<byte> receivedHmac = packet.Slice(integrityValueOffset, MessageIntegritySize);

//    Span<byte> covered = stackalloc byte[integrityAttributeOffset];
//    packet.Slice(0, integrityAttributeOffset).CopyTo(covered);
//    BinaryPrimitives.WriteUInt16BigEndian(covered.Slice(2), (ushort) (integrityAttributeOffset - HeaderSize + 4 + MessageIntegritySize));

//    Span<byte> computedHmac = stackalloc byte[MessageIntegritySize];
//    HMACSHA1.HashData(integrityKey, covered, computedHmac);

//    return CryptographicOperations.FixedTimeEquals(receivedHmac, computedHmac);
//   }

//   private static int WriteAttributeHeader(Span<byte> destination, ushort attributeType, ushort valueLength)
//   {
//    BinaryPrimitives.WriteUInt16BigEndian(destination, attributeType);
//    BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2), valueLength);
//    return 4;
//   }

//   private static int WriteXorMappedAddress(Span<byte> destination, IPEndPoint endPoint, byte[] transactionId)
//   {
//    bool isIPv4 = endPoint.AddressFamily == AddressFamily.InterNetwork;
//    int addressLength = isIPv4 ? 4 : 16;
//    int valueLength = 4 + addressLength;

//    int written = WriteAttributeHeader(destination, AttributeXorMappedAddress, (ushort) valueLength);
//    Span<byte> value = destination.Slice(written, valueLength);

//    value[0] = 0;
//    value[1] = isIPv4 ? FamilyIPv4 : FamilyIPv6;
//    ushort xorPort = (ushort) (endPoint.Port ^ (int) (MagicCookie >> 16));
//    BinaryPrimitives.WriteUInt16BigEndian(value.Slice(2), xorPort);

//    Span<byte> xorPad = stackalloc byte[16];
//    BinaryPrimitives.WriteUInt32BigEndian(xorPad, MagicCookie);
//    if (!isIPv4) transactionId.AsSpan().CopyTo(xorPad.Slice(4));

//    Span<byte> addressBytes = stackalloc byte[16];
//    endPoint.Address.TryWriteBytes(addressBytes, out _);

//    for (int i = 0; i < addressLength; i++)
//    {
//     value[4 + i] = (byte) (addressBytes[i] ^ xorPad[i]);
//    }

//    return written + valueLength;
//   }

//   private static IPEndPoint ParseXorMappedAddress(ReadOnlySpan<byte> value, byte[] transactionId)
//   {
//    if (value.Length < 4) throw new FormatException("XOR-MAPPED-ADDRESS attribute too short");

//    byte family = value[1];
//    int addressLength = family switch
//    {
//     FamilyIPv4 => 4,
//     FamilyIPv6 => 16,
//     _ => throw new FormatException($"Unknown XOR-MAPPED-ADDRESS family {family}")
//    };

//    if (value.Length < 4 + addressLength) throw new FormatException("XOR-MAPPED-ADDRESS attribute too short");

//    int port = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(2)) ^ (int) (MagicCookie >> 16);

//    Span<byte> xorPad = stackalloc byte[16];
//    BinaryPrimitives.WriteUInt32BigEndian(xorPad, MagicCookie);
//    if (family == FamilyIPv6) transactionId.AsSpan().CopyTo(xorPad.Slice(4));

//    Span<byte> addressBytes = stackalloc byte[16];
//    for (int i = 0; i < addressLength; i++)
//    {
//     addressBytes[i] = (byte) (value[4 + i] ^ xorPad[i]);
//    }

//    var address = new IPAddress(addressBytes.Slice(0, addressLength));
//    return new IPEndPoint(address, port);
//   }
//  }
// }
