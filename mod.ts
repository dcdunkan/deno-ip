import { Buffer } from "https://deno.land/std@0.147.0/node/buffer.ts";
import { networkInterfaces } from "https://deno.land/std@0.147.0/node/os.ts";

export function toBuffer(ip: string, buff?: Buffer, offset?: number): Buffer {
  offset = ~~offset!;
  let result!: Buffer;

  if (isV4Format(ip)) {
    result = buff ?? Buffer.alloc(offset + 4);
    ip.split(/\./g).map((byte) => {
      result[offset!++] = parseInt(byte, 10) & 0xff;
    });
  } else if (isV6Format(ip)) {
    const sections = ip.split(":", 8);

    let i;
    for (i = 0; i < sections.length; i++) {
      const isv4 = isV4Format(sections[i]);
      let v4Buffer;

      if (isv4) {
        v4Buffer = toBuffer(sections[i]);
        sections[i] = v4Buffer.slice(0, 2).toString("hex");
      }

      if (v4Buffer && ++i < 8) {
        sections.splice(i, 0, v4Buffer.slice(2, 4).toString("hex"));
      }
    }

    if (sections[0] === "") {
      while (sections.length < 8) sections.unshift("0");
    } else if (sections[sections.length - 1] === "") {
      while (sections.length < 8) sections.push("0");
    } else if (sections.length < 8) {
      for (i = 0; i < sections.length && sections[i] !== ""; i++);
      const argv: Array<string | number> = [i, 1];
      for (i = 9 - sections.length; i > 0; i--) {
        argv.push("0");
      }
      sections.splice(...(argv as [number, number]));
    }

    result = buff || Buffer.alloc(offset + 16);
    for (i = 0; i < sections.length; i++) {
      const word = parseInt(sections[i], 16);
      result[offset++] = (word >> 8) & 0xff;
      result[offset++] = word & 0xff;
    }
  }

  if (!result) {
    throw Error(`Invalid ip address: ${ip}`);
  }

  return result;
}

export function toString(buff: Buffer, offset?: number, length?: number) {
  offset = ~~offset!;
  length = length || (buff.length - offset);

  const resultArr = new Array<string>();
  let result = "";
  if (length === 4) {
    for (let i = 0; i < length; i++) {
      resultArr.push(`${buff[offset + i]}`);
    }
    result = resultArr.join(".");
  } else if (length === 16) {
    // IPv6
    for (let i = 0; i < length; i += 2) {
      resultArr.push(buff.readUInt16BE(offset + i).toString(16));
    }
    result = resultArr.join(":");
    result = result.replace(/(^|:)0(:0)*:0(:|$)/, "$1::$3");
    result = result.replace(/:{3,4}/, "::");
  }

  return result;
}

const ipv4Regex = /^(\d{1,3}\.){3,3}\d{1,3}$/;
const ipv6Regex =
  /^(::)?(((\d{1,3}\.){3}(\d{1,3}){1})?([0-9a-f]){0,4}:{0,2}){1,8}(::)?$/i;

export function isV4Format(ip: string) {
  return ipv4Regex.test(ip);
}

export function isV6Format(ip: string) {
  return ipv6Regex.test(ip);
}

function _normalizeFamily(family: 4 | 6 | string = "ipv4") {
  if (family === 4) {
    return "ipv4";
  }
  if (family === 6) {
    return "ipv6";
  }
  return family ? family.toLowerCase() : "ipv4";
}

export function fromPrefixLen(prefixLen: number, family?: string | 4 | 6) {
  if (prefixLen > 32) {
    family = "ipv6";
  } else {
    family = _normalizeFamily(family!);
  }

  let len = 4;
  if (family === "ipv6") {
    len = 16;
  }
  const buff = Buffer.alloc(len);

  for (let i = 0, n = buff.length; i < n; ++i) {
    let bits = 8;
    if (prefixLen < 8) {
      bits = prefixLen;
    }
    prefixLen -= bits;

    buff[i] = ~(0xff >> bits) & 0xff;
  }

  return toString(buff);
}

export function mask(addrStr: string, maskStr: string) {
  const addr = toBuffer(addrStr);
  const mask = toBuffer(maskStr);

  const result = Buffer.alloc(Math.max(addr.length, mask.length));

  // Same protocol - do bitwise and
  let i;
  if (addr.length === mask.length) {
    for (i = 0; i < addr.length; i++) {
      result[i] = addr[i] & mask[i];
    }
  } else if (mask.length === 4) {
    // IPv6 address and IPv4 mask
    // (Mask low bits)
    for (i = 0; i < mask.length; i++) {
      result[i] = addr[addr.length - 4 + i] & mask[i];
    }
  } else {
    // IPv6 mask and IPv4 addr
    for (i = 0; i < result.length - 6; i++) {
      result[i] = 0;
    }

    // ::ffff:ipv4
    result[10] = 0xff;
    result[11] = 0xff;
    for (i = 0; i < addr.length; i++) {
      result[i + 12] = addr[i] & mask[i + 12];
    }
    i += 12;
  }
  for (; i < result.length; i++) {
    result[i] = 0;
  }

  return toString(result);
}

export function cidr(cidrString: string) {
  const cidrParts = cidrString.split("/");

  const addr = cidrParts[0];
  if (cidrParts.length !== 2) {
    throw new Error(`invalid CIDR subnet: ${addr}`);
  }

  const maskStr = fromPrefixLen(parseInt(cidrParts[1], 10));

  return mask(addr, maskStr);
}

export interface SubnetInfo {
  networkAddress: string;
  firstAddress: string;
  lastAddress: string;
  broadcastAddress: string;
  subnetMask: string;
  subnetMaskLength: number;
  numHosts: number;
  length: number;
  contains(ip: string): boolean;
}

export function subnet(addr: string, maskStr: string): SubnetInfo {
  const networkAddress = toLong(mask(addr, maskStr));

  // Calculate the mask's length.
  const maskBuffer = toBuffer(maskStr);
  let maskLength = 0;

  for (let i = 0; i < maskBuffer.length; i++) {
    if (maskBuffer[i] === 0xff) {
      maskLength += 8;
    } else {
      let octet = maskBuffer[i] & 0xff;
      while (octet) {
        octet = (octet << 1) & 0xff;
        maskLength++;
      }
    }
  }

  const numberOfAddresses = 2 ** (32 - maskLength);

  return {
    networkAddress: fromLong(networkAddress),
    firstAddress: numberOfAddresses <= 2
      ? fromLong(networkAddress)
      : fromLong(networkAddress + 1),
    lastAddress: numberOfAddresses <= 2
      ? fromLong(networkAddress + numberOfAddresses - 1)
      : fromLong(networkAddress + numberOfAddresses - 2),
    broadcastAddress: fromLong(networkAddress + numberOfAddresses - 1),
    subnetMask: maskStr,
    subnetMaskLength: maskLength,
    numHosts: numberOfAddresses <= 2
      ? numberOfAddresses
      : numberOfAddresses - 2,
    length: numberOfAddresses,
    contains(other: string) {
      return networkAddress === toLong(mask(other, maskStr));
    },
  };
}

export function cidrSubnet(cidrString: string) {
  const cidrParts = cidrString.split("/");
  const addr = cidrParts[0];
  if (cidrParts.length !== 2) {
    throw new Error(`invalid CIDR subnet: ${addr}`);
  }
  const mask = fromPrefixLen(parseInt(cidrParts[1], 10));
  return subnet(addr, mask);
}

export function not(addr: string) {
  const buff = toBuffer(addr);
  for (let i = 0; i < buff.length; i++) {
    buff[i] = 0xff ^ buff[i];
  }
  return toString(buff);
}

export function or(aStr: string, bStr: string) {
  const a = toBuffer(aStr);
  const b = toBuffer(bStr);

  // same protocol
  if (a.length === b.length) {
    for (let i = 0; i < a.length; ++i) {
      a[i] |= b[i];
    }
    return toString(a);

    // mixed protocols
  }
  let buff = a;
  let other = b;
  if (b.length > a.length) {
    buff = b;
    other = a;
  }

  const offset = buff.length - other.length;
  for (let i = offset; i < buff.length; ++i) {
    buff[i] |= other[i - offset];
  }

  return toString(buff);
}

export function isEqual(aStr: string, bStr: string) {
  let a = toBuffer(aStr);
  let b = toBuffer(bStr);

  // Same protocol
  if (a.length === b.length) {
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  // Swap
  if (b.length === 4) {
    const t = b;
    b = a;
    a = t;
  }

  // a - IPv4, b - IPv6
  for (let i = 0; i < 10; i++) {
    if (b[i] !== 0) return false;
  }

  const word = b.readUInt16BE(10);
  if (word !== 0 && word !== 0xffff) return false;

  for (let i = 0; i < 4; i++) {
    if (a[i] !== b[i + 12]) return false;
  }

  return true;
}

export function isPrivate(addr: string) {
  return /^(::f{4}:)?10\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i
    .test(addr) ||
    /^(::f{4}:)?192\.168\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
    /^(::f{4}:)?172\.(1[6-9]|2\d|30|31)\.([0-9]{1,3})\.([0-9]{1,3})$/i
      .test(addr) ||
    /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
    /^(::f{4}:)?169\.254\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
    /^f[cd][0-9a-f]{2}:/i.test(addr) ||
    /^fe80:/i.test(addr) ||
    /^::1$/.test(addr) ||
    /^::$/.test(addr);
}

export function isPublic(addr: string) {
  return !isPrivate(addr);
}

export function isLoopback(addr: string) {
  return /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/
    .test(addr) ||
    /^fe80::1$/.test(addr) ||
    /^::1$/.test(addr) ||
    /^::$/.test(addr);
}

export function loopback(family = "ipv4") {
  family = _normalizeFamily(family);
  if (family !== "ipv4" && family !== "ipv6") {
    throw new Error("family must be ipv4 or ipv6");
  }
  return family === "ipv4" ? "127.0.0.1" : "fe80::1";
}

export function address(name?: string, family?: string) {
  const interfaces = networkInterfaces();

  family = _normalizeFamily(family);
  if (name && name !== "private" && name !== "public") {
    const res = interfaces[name].filter((details) => {
      const itemFamily = _normalizeFamily(details.family);
      return itemFamily === family;
    });
    if (res.length === 0) {
      return undefined;
    }
    return res[0].address;
  }

  const all = Object.keys(interfaces).map((nic) => {
    const addresses = interfaces[nic].filter((details) => {
      details.family = _normalizeFamily(details.family) as "IPv4" | "IPv6";
      if (details.family !== family || isLoopback(details.address)) {
        return false;
      }
      if (!name) return true;
      return name === "public"
        ? isPublic(details.address)
        : isPrivate(details.address);
    });

    return addresses.length ? addresses[0].address : undefined;
  }).filter(Boolean);

  return !all.length ? loopback(family) : all[0];
}

export function toLong(ip: string) {
  let ipl = 0;
  ip.split(".").forEach((octet) => {
    ipl <<= 8;
    ipl += parseInt(octet);
  });
  return (ipl >>> 0);
}

export function fromLong(ipl: number) {
  return (`${ipl >>> 24}.${ipl >> 16 & 255}.${ipl >> 8 & 255}.${ipl & 255}`);
}
