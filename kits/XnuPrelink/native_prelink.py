#!/usr/bin/env python3
"""Plan ordinary ARM64 prelink pointer rebinding; never changes input images."""
import argparse
import base64
from bisect import bisect_right
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import xml.etree.ElementTree as ET


def macho(data, at=0):
    if at < 0 or at + 32 > len(data):
        raise ValueError('Mach-O header outside image')
    magic, cpu, subtype, kind, count, size = struct.unpack_from('<6I', data, at)
    # subtype 0 = plain arm64 (the 20H392/21H461 caches); base subtype 2 with
    # the pointer-auth version in the top two bits = arm64e (the 21H16
    # iPhone11,2 cache and every component embedded in it). The arm64e
    # component code is copied unchanged; its PAC instructions are
    # self-balanced, so the host CPU only needs FEAT_PAuth. Refuse anything
    # outside these two so a new shape fails loudly here.
    if magic != 0xfeedfacf or cpu != 0x100000c or subtype & 0x3FFFFFFF not in (0, 2):
        raise ValueError(f'Only little-endian ARM64/arm64e is supported, got cpu {cpu:#x} subtype {subtype:#x}')
    end = at + 32 + size
    if end > len(data):
        raise ValueError('Load commands outside image')
    offset = at + 32
    commands, segments = [], []
    for _ in range(count):
        if offset + 8 > end:
            raise ValueError('Truncated load command')
        command, length = struct.unpack_from('<II', data, offset)
        if length < 8 or length % 8 or offset + length > end:
            raise ValueError('Invalid load command extent')
        commands.append((command, offset, length))
        if command == 0x19:
            if length < 72:
                raise ValueError('Truncated segment')
            name, va, size, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from('<16s4Q4I', data, offset + 8)
            if length != 72 + 80 * nsects or filesize > size or va + size > 1 << 64:
                raise ValueError('Invalid segment extent')
            segments.append({'name': name.rstrip(b'\0').decode(), 'va': va, 'size': size,
                             'fileoff': fileoff, 'filesize': filesize, 'command_offset': offset,
                             'maxprot': maxprot, 'initprot': initprot, 'sections': []})
            for index in range(nsects):
                section_at = offset + 72 + index * 80
                section_name, _, address, extent, section_offset = struct.unpack_from('<16s16sQQI', data, section_at)
                if extent and not va <= address <= address + extent <= va + size:
                    raise ValueError('Section outside segment')
                segments[-1]['sections'].append({'name': section_name.rstrip(b'\0').decode(),
                    'va': address, 'size': extent, 'fileoff': section_offset, 'command_offset': section_at})
        offset += length
    if offset != end:
        raise ValueError('Load command size mismatch')
    return {'kind': kind, 'segments': segments, 'commands': commands}


def backed_offset(segments, address, length, data_length):
    matches = [s['fileoff'] + address - s['va'] for s in segments
               if s['va'] <= address and address + length <= s['va'] + s['filesize']]
    if len(matches) != 1 or matches[0] + length > data_length:
        raise ValueError(f'Ambiguous or unbacked address {address:#x}+{length:#x}')
    return matches[0]


def exports(data, image):
    result = {}
    tables = [(offset, length) for command, offset, length in image['commands'] if command == 2]
    if len(tables) != 1 or tables[0][1] != 24:
        raise ValueError('Expected one symbol table')
    symoff, count, stroff, strsize = struct.unpack_from('<4I', data, tables[0][0] + 8)
    if symoff + count * 16 > len(data) or stroff + strsize > len(data):
        raise ValueError('Symbol table outside image')
    strings = data[stroff:stroff + strsize]
    for index in range(count):
        strx, kind, _, _, address = struct.unpack_from('<IBBHQ', data, symoff + index * 16)
        if kind & 0xe0 or not kind & 1 or not kind & 0x0e:
            continue
        end = strings.find(b'\0', strx)
        if strx >= strsize or end < 0:
            raise ValueError('Unterminated symbol name')
        name = strings[strx:end].decode()
        result.setdefault(address, []).append(name)
    return result


def unserialize_xml(blob):
    refs = {}

    def read(element):
        if 'IDREF' in element.attrib:
            return refs[element.attrib['IDREF']]
        tag = element.tag
        if tag == 'dict':
            children = list(element)
            if len(children) % 2:
                raise ValueError('Odd XML dictionary')
            value = {}
            for index in range(0, len(children), 2):
                key = read(children[index])
                if key in value:
                    raise ValueError('Duplicate XML dictionary key')
                value[key] = read(children[index + 1])
        elif tag == 'array':
            value = [read(child) for child in element]
        elif tag in ('key', 'string'):
            value = element.text or ''
        elif tag == 'integer':
            value = int(element.text or '0', 0)
        elif tag == 'data':
            value = base64.b64decode(''.join((element.text or '').split()), validate=True)
        elif tag in ('true', 'false'):
            value = tag == 'true'
        else:
            raise ValueError(f'Unsupported prelink XML element {tag}')
        if 'ID' in element.attrib:
            identifier = element.attrib['ID']
            if identifier in refs:
                raise ValueError('Duplicate XML object ID')
            refs[identifier] = value
        return value

    element = ET.fromstring(blob.split(b'\0', 1)[0])
    # The 21H16 cache wraps its prelink dictionary in a <plist> element (the
    # earlier caches carry the bare dict); unwrap it so both shapes parse.
    if element.tag == 'plist':
        children = list(element)
        if len(children) != 1 or children[0].tag != 'dict':
            raise ValueError('Unexpected <plist> payload in prelink metadata')
        element = children[0]
    return read(element)


def u64(value):
    # The 21H16 fileset cache stores its prelink addresses as signed decimal
    # (e.g. -68601184256); the 64-bit two's complement is the real VA.
    return value & (1 << 64) - 1 if isinstance(value, int) else value


def chain_relocations(data, image):
    """Decode a fileset cache's dyld chained fixups into (site, target) pairs.

    The 21H16 cache is a fully linked MH_FILESET collection: no binds, only
    rebase chains (pointer_format 8, auth and plain). Entries follow the
    standard dyld_chained_ptr_64_auth_rebase bit layout with one deviation
    verified against all 419,323 real entries: the next field counts 4-byte
    units, not bytes.
    """
    commands = [command for command in image['commands'] if command[0] == 0x80000034]
    if len(commands) != 1:
        raise ValueError('Expected one LC_DYLD_CHAINED_FIXUPS command')
    dataoff, datasize = struct.unpack_from('<II', data, commands[0][1] + 8)
    if dataoff + datasize > len(data):
        raise ValueError('Chained fixups blob outside image')
    version, starts_offset, imports_offset, symbols_offset, imports_count, imports_format, symbols_format = \
        struct.unpack_from('<7I', data, dataoff)
    if version != 0:
        raise ValueError(f'Unsupported chained fixups version {version}')
    if imports_count or symbols_format:
        raise ValueError('Fileset cache must be fully linked: chained binds are not supported')
    count, = struct.unpack_from('<I', data, dataoff + starts_offset)
    base = next(s['va'] for s in image['segments'] if s['name'] == '__TEXT')
    candidates, seen = [], set()
    for index in range(count):
        relative, = struct.unpack_from('<I', data, dataoff + starts_offset + 4 + 4 * index)
        if not relative:
            continue
        at = dataoff + starts_offset + relative
        extent, page_size, pointer_format = struct.unpack_from('<IHH', data, at)
        if starts_offset + relative + extent > datasize:
            raise ValueError('Chained segment header outside fixups blob')
        if pointer_format != 8:
            raise ValueError(f'Unsupported chained pointer format {pointer_format}')
        if page_size != 16384:
            raise ValueError(f'Unsupported chained fixup page size {page_size}')
        segment_offset, = struct.unpack_from('<Q', data, at + 8)
        segment = next((s for s in image['segments'] if s['va'] - base == segment_offset), None)
        if segment is None:
            raise ValueError(f'Chained fixups segment offset {segment_offset:#x} outside image')
        page_count, = struct.unpack_from('<H', data, at + 20)
        pages = struct.unpack_from(f'<{page_count}H', data, at + 22)
        if page_count * page_size < segment['filesize']:
            raise ValueError(f'Chained fixup pages do not cover {segment["name"]}')
        for page_index, start in enumerate(pages):
            if start == 0xFFFF:
                continue
            cursor = segment['fileoff'] + page_index * page_size + start
            hops = 0
            while True:
                offset = cursor - segment['fileoff']
                # Entries sit on 4-byte boundaries: the 457 four-mod-eight
                # real sites include kmod_info start/stop at +180/+188.
                if offset % 4 or not 0 <= offset < segment['filesize']:
                    raise ValueError(f'Chained fixup entry outside {segment["name"]} file data')
                if cursor in seen:
                    raise ValueError('Duplicate pointer relocation site')
                seen.add(cursor)
                word, = struct.unpack_from('<Q', data, cursor)
                meta = word >> 32
                if not meta >> 31 and meta & 0x7FFFF:
                    raise ValueError(f'Unexplained plain chained fixup metadata {meta:#x} in {segment["name"]}')
                candidates.append((segment['va'] + offset, base + (word & 0xFFFFFFFF)))
                following = (meta >> 19) & 0xFFF
                if not following:
                    break
                cursor += following * 4
                hops += 1
                if hops > 4096:
                    raise ValueError('Runaway chained fixup chain')
    return candidates


def unique_kernel_binding(address, original_exports, native_by_name):
    names = original_exports.get(address, [])
    choices = {new for name in names for new in native_by_name.get(name, set())}
    if len(choices) != 1:
        raise ValueError(f'Kernel target {address:#x} has {len(choices)} native address candidates: {names}')
    return next(iter(choices))


def plan(native_data, original_data, roots, slide, original_symbols=None):
    if slide % 4096:
        raise ValueError('Rebasing must preserve native 4K alignment')
    native, original = macho(native_data), macho(original_data)
    if native['kind'] != 2:
        raise ValueError('Expected MH_EXECUTE kernel images')
    if original['kind'] not in (2, 12):
        raise ValueError('Expected an MH_EXECUTE kernelcache or an MH_FILESET collection')
    fileset = original['kind'] == 12
    parent = original['segments']
    info = next(s for s in parent if s['name'] == '__PRELINK_INFO')
    at = backed_offset(parent, u64(info['va']), info['filesize'], len(original_data))
    metadata = unserialize_xml(original_data[at:at + info['filesize']])
    entries = {}
    for entry in metadata['_PrelinkInfoDictionary']:
        identifier = entry['CFBundleIdentifier']
        if identifier in entries:
            raise ValueError('Duplicate prelink identifier')
        entries[identifier] = entry
    selected, interfaces = set(), set()
    pending = list(roots)
    while pending:
        identifier = pending.pop()
        if identifier in selected or identifier in interfaces:
            continue
        if identifier not in entries:
            raise ValueError(f'Missing declared dependency {identifier}')
        entry = entries[identifier]
        if entry.get('OSKernelResource') is True:
            interfaces.add(identifier)
            continue
        selected.add(identifier)
        pending.extend(entry.get('OSBundleLibraries') or {})
    owned, modules = [], {}
    for identifier, entry in entries.items():
        if entry.get('OSKernelResource') is True:
            continue
        va = u64(entry.get('_PrelinkExecutableLoadAddr'))
        if va is None or not entry.get('_PrelinkExecutableSize'):
            continue
        header = backed_offset(parent, va, 32, len(original_data))
        module = macho(original_data, header)
        if module['kind'] != 11:
            raise ValueError('Expected MH_KEXT_BUNDLE component')
        modules[identifier] = module
        for segment in module['segments']:
            if segment['size'] and segment['name'] != '__LINKEDIT':
                owned.append((segment['va'], segment['va'] + segment['size'], identifier, segment))
    codeless = selected - modules.keys()
    for identifier in codeless:
        entry = entries[identifier]
        executable_keys = ('CFBundleExecutable', '_PrelinkExecutableLoadAddr',
            '_PrelinkExecutableSourceAddr', '_PrelinkExecutableSize', '_PrelinkKmodInfo')
        if any(key in entry for key in executable_keys) or not isinstance(entry.get('IOKitPersonalities'), dict) or not entry['IOKitPersonalities']:
            raise ValueError('Codeless component must contain personalities and no executable fields: ' + identifier)
    owned.sort(key=lambda item: item[:3])
    for left, right in zip(owned, owned[1:]):
        if left[1] > right[0]:
            raise ValueError(f'Overlapping component extents: {left[2]} and {right[2]}')
    starts = [item[0] for item in owned]

    def owner(address):
        index = bisect_right(starts, address) - 1
        return owned[index] if index >= 0 and address < owned[index][1] else None

    native_symbols = {}
    for address, names in exports(native_data, native).items():
        for name in names:
            native_symbols.setdefault(name, set()).add(address)
    # Kernel targets are bound by name. Classical caches carry the donor's
    # export symbol table; the 21H16 fileset release cache is fully stripped,
    # so the caller must supply a KDK-derived {va: name} side table instead.
    if fileset:
        if original_symbols is None:
            raise ValueError('Fileset release caches carry no kernel symbol table; a KDK-derived side table is required')
        candidates = chain_relocations(original_data, original)
    else:
        packed = metadata.get('_PrelinkLinkKASLROffsets')
        if packed is None:
            raise ValueError('Missing _PrelinkLinkKASLROffsets pointer table')
        if original_symbols is None:
            original_symbols = exports(original_data, original)
        count, = struct.unpack_from('<I', packed)
        if len(packed) != 4 + count * 4:
            raise ValueError('Invalid pointer-table extent')
        offsets = struct.unpack_from(f'<{count}I', packed, 4)
        if len(set(offsets)) != count:
            raise ValueError('Duplicate pointer relocation site')
        base = next(s['va'] for s in parent if s['name'] == '__PRELINK_TEXT')
        candidates = []
        for offset in offsets:
            site = base + offset
            target, = struct.unpack_from('<Q', original_data, backed_offset(parent, site, 8, len(original_data)))
            candidates.append((site, target))
    bindings = []
    for site, target in candidates:
        source = owner(site)
        if source is None or source[2] not in selected:
            continue
        if source != owner(site + 7):
            raise ValueError('Pointer spans component extent')
        destination = owner(target)
        if destination:
            if destination[2] not in selected:
                raise ValueError(f'Undeclared pointer dependency {destination[2]} from {source[2]}')
            replacement = target + slide
            kind = 'component'
        else:
            replacement = unique_kernel_binding(target, original_symbols, native_symbols)
            if not any(s['va'] <= replacement < s['va'] + s['size'] for s in native['segments']):
                raise ValueError('Native export is outside mapped kernel segments')
            kind = 'kernel'
        if not 0 <= site + slide < 1 << 64 or not 0 <= replacement < 1 << 64:
            raise ValueError('Rebased pointer outside 64-bit address space')
        bindings.append({'site': site, 'target': target, 'new_site': site + slide,
                         'new_target': replacement, 'kind': kind, 'module': source[2]})
    if fileset:
        # kmod_info start/stop are chained rebase entries in a fileset cache,
        # so their original values come from the decoded bindings, not raw
        # reads. A zero start/stop has no chain entry and stays zero.
        decoded = {binding['site']: binding['target'] for binding in bindings}
        kmod_entrypoints = {}
        for identifier in modules:
            va = u64(entries[identifier].get('_PrelinkKmodInfo'))
            if not va:
                continue
            start, stop = decoded.get(va + 180, 0), decoded.get(va + 188, 0)
            for name, address in (('start', start), ('stop', stop)):
                if address:
                    holder = owner(address)
                    if holder is None or holder[2] != identifier:
                        raise ValueError(f'kmod_info {name} of {identifier} does not decode inside {identifier}')
            kmod_entrypoints[identifier] = {'start': start, 'stop': stop}
    else:
        kmod_entrypoints = None
    extents = []
    for start, end, identifier, segment in owned:
        if identifier not in selected:
            continue
        if not 0 <= start + slide < end + slide <= 1 << 64:
            raise ValueError('Rebased segment outside 64-bit address space')
        for s in native['segments']:
            if s['size'] and start + slide < s['va'] + s['size'] and s['va'] < end + slide:
                raise ValueError(f'Rebased component collides with native {s["name"]}')
        extents.append({'module': identifier, 'segment': segment['name'],
                        'va': start + slide, 'size': end - start})
    return {'native_sha256': hashlib.sha256(native_data).hexdigest(),
            'original_sha256': hashlib.sha256(original_data).hexdigest(),
            'slide': slide, 'components': sorted(selected - codeless),
            'codeless_components': sorted(codeless), 'kernel_interfaces': sorted(interfaces),
            'pointer_counts': dict(Counter(binding['kind'] for binding in bindings)),
            'extents': extents, 'bindings': bindings, 'images_modified': False,
            'kmod_entrypoints': kmod_entrypoints,
            'instruction_relocation_complete': False, 'abi_qualified': False, 'loadable': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--prelinked', required=True, type=Path)
    parser.add_argument('--root', required=True, action='append')
    parser.add_argument('--slide', required=True, type=lambda value: int(value, 0))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = plan(args.kernel.read_bytes(), args.prelinked.read_bytes(), args.root, args.slide)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('components', 'kernel_interfaces', 'pointer_counts', 'loadable')}, indent=2))


if __name__ == '__main__':
    main()
