#!/usr/bin/env python3
"""Synthetic fileset kernelcache (21H16 shape) test chained-fixups rebinding."""
import struct
import unittest
import xml.etree.ElementTree as ET

from emit_prelink import emit
from native_prelink import chain_relocations, macho, plan
from test_emit_prelink import images as emit_images
from test_native_prelink import header, segment, xml_value

BASE = 0xfffffff007004000
KERNEL_TARGET = BASE + 0x800
SIDE_TABLE = {KERNEL_TARGET: ['_kpi']}
SLIDE = 0x4000


def chain_word(target32, *, auth=0, key=0, diversity=0, addr_div=0, next_units=0):
    return (target32 | diversity << 32 | addr_div << 48 | key << 49
            | next_units << 51 | auth << 63)


def fileset_fixture(*, pointer_format=8, plain_meta=False):
    segment_entry = struct.pack('<IHHQI', 26, 16384, pointer_format, 0x3000, 0x2000)
    segment_entry += struct.pack('<H', 2) + struct.pack('<2H', 0x1B4, 0xFFFF)
    # dyld_chained_starts_in_image: seg_count then one offset per segment.
    # The chain entries themselves live in the segment data the page starts
    # point into; the blob only carries the walk metadata.
    blob = struct.pack('<7I', 0, 28, 28, 28, 0, 0, 0) + struct.pack('<2I', 1, 8)
    blob += segment_entry
    format_at = 28 + 8 + 6  # pointer_format u16 inside the segment entry

    original = bytearray(0x9000)
    commands = [segment('__TEXT', BASE, 0x1000, 0, 0x1000),
                segment('__PRELINK_TEXT', BASE + 0x1000, 0x2000, 0x1000, 0x2000),
                segment('__DATA_CONST', BASE + 0x3000, 0x2000, 0x3000, 0x2000),
                segment('__PLK_TEXT_EXEC', BASE + 0x5000, 0x1000, 0x5000, 0x1000)]
    dataoff = 0x8100
    commands.append(segment('__PRELINK_INFO', BASE + 0x6000, 0x1000, 0x6000, 0x1000))
    commands.append(segment('__PRELINK_DATA', BASE + 0x7000, 0x1000, 0x7000, 0x1000))
    commands.append(segment('__LINKEDIT', BASE + 0x8000, 0x1000, 0x8000, 0x1000))
    commands.append(struct.pack('<IIII', 0x80000034, 16, dataoff, len(blob)))
    original[:len(header(12, commands))] = header(12, commands)

    # Component A: __TEXT at BASE+0x1000 and __DATA_CONST holding its
    # kmod_info at BASE+0x3100 (start/stop chained, 4-mod-8 sites).
    component_a = header(11, [segment('__TEXT', BASE + 0x1000, 0x800, 0x1000, 0x800),
                              segment('__DATA_CONST', BASE + 0x3000, 0x1000, 0x3000, 0x1000)])
    original[0x1000:0x1000 + len(component_a)] = component_a
    # Component B: __TEXT only, referenced by A's authenticated pointer.
    component_b = header(11, [segment('__TEXT', BASE + 0x1800, 0x800, 0x1800, 0x800)])
    original[0x1800:0x1800 + len(component_b)] = component_b
    struct.pack_into('<Q', original, 0x3100 + 156, BASE + 0x1000)
    struct.pack_into('<Q', original, 0x1C00 + 156, 0)  # B kmod address: none
    # The chain itself lives in A's __DATA_CONST: kmod start (auth) -> kmod
    # stop (auth, a 4-mod-8 site) -> kernel function (plain).
    chain = [chain_word(0x1080, auth=1, diversity=0x1234, addr_div=1, next_units=2),
             chain_word(0x1080, auth=1, next_units=2),
             chain_word(0x800)]
    if plain_meta:
        chain[-1] |= 0x4321 << 32
    struct.pack_into('<3Q', original, 0x31B4, *chain)

    # Metadata addresses use the real cache's signed-decimal representation.
    entries = [{'CFBundleIdentifier': 'test.a',
                '_PrelinkExecutableLoadAddr': (BASE + 0x1000) - (1 << 64),
                '_PrelinkExecutableSourceAddr': (BASE + 0x1000) - (1 << 64),
                '_PrelinkExecutableSize': 0x800,
                '_PrelinkKmodInfo': (BASE + 0x3100) - (1 << 64),
                'OSBundleLibraries': {'test.b': '1'}},
               {'CFBundleIdentifier': 'test.b',
                '_PrelinkExecutableLoadAddr': (BASE + 0x1800) - (1 << 64),
                '_PrelinkExecutableSourceAddr': (BASE + 0x1800) - (1 << 64),
                '_PrelinkExecutableSize': 0x800,
                '_PrelinkKmodInfo': (BASE + 0x1C00) - (1 << 64)}]
    xml = ET.tostring(xml_value({'_PrelinkInfoDictionary': entries})) + b'\0'
    original[0x6000:0x6000 + len(xml)] = xml
    original[dataoff:dataoff + len(blob)] = blob
    return bytes(original), dataoff + format_at, 0x31B4 + 20


class FilesetTests(unittest.TestCase):
    def setUp(self):
        self.native = emit_images()[0]

    def test_chain_decode_and_binding(self):
        original, _, _ = fileset_fixture()
        sites = chain_relocations(original, macho(original))
        self.assertEqual([site for site, _ in sites],
                         [BASE + 0x31B4, BASE + 0x31BC, BASE + 0x31C4])
        report = plan(self.native, original, ['test.a'], SLIDE, SIDE_TABLE)
        self.assertEqual(report['components'], ['test.a', 'test.b'])
        self.assertEqual(report['pointer_counts'], {'component': 2, 'kernel': 1})
        self.assertEqual([b['new_target'] for b in report['bindings']],
                         [BASE + 0x1080 + SLIDE, BASE + 0x1080 + SLIDE, 0x100800])
        self.assertEqual(report['kmod_entrypoints'], {
            'test.a': {'start': BASE + 0x1080, 'stop': BASE + 0x1080},
            'test.b': {'start': 0, 'stop': 0}})

    def test_emit_rebases_chained_sites(self):
        original, _, _ = fileset_fixture()
        output, report = emit(self.native, original, ['test.a'], SLIDE, {}, SIDE_TABLE)
        self.assertEqual(report['module_entrypoints']['test.a']['start_va'], BASE + 0x1080 + SLIDE)
        segment = next(s for s in macho(output)['segments'] if s['name'] == '__PLK_DATA_CONST')
        # The rebased chain sites now hold plain absolute pointers.
        self.assertEqual(struct.unpack_from('<Q', output, segment['fileoff'] + 0x1B4)[0], BASE + 0x1080 + SLIDE)
        self.assertEqual(struct.unpack_from('<Q', output, segment['fileoff'] + 0x1C4)[0], 0x100800)
        self.assertEqual(struct.unpack_from('<Q', output, segment['fileoff'] + 0x100 + 156)[0], BASE + 0x1000 + SLIDE)

    def test_refuse_missing_symbol_side_table(self):
        original, _, _ = fileset_fixture()
        with self.assertRaisesRegex(ValueError, 'KDK-derived side table'):
            plan(self.native, original, ['test.a'], SLIDE)

    def test_refuse_unknown_pointer_format(self):
        original, format_at, _ = fileset_fixture(pointer_format=7)
        self.assertEqual(struct.unpack_from('<H', original, format_at)[0], 7)
        with self.assertRaisesRegex(ValueError, 'Unsupported chained pointer format 7'):
            plan(self.native, original, ['test.a'], SLIDE, SIDE_TABLE)

    def test_refuse_unexplained_plain_metadata(self):
        original, _, meta_at = fileset_fixture(plain_meta=True)
        self.assertEqual(struct.unpack_from('<H', original, meta_at)[0], 0x4321)
        with self.assertRaisesRegex(ValueError, 'Unexplained plain chained fixup metadata'):
            plan(self.native, original, ['test.a'], SLIDE, SIDE_TABLE)

    def test_refuse_metadata_without_kaslr_table(self):
        # A classical cache without the pointer table must fail loudly, not
        # silently fall back to chained-fixups discovery.
        classical = bytearray(fileset_fixture()[0])
        classical[12:16] = struct.pack('<I', 2)  # MH_EXECUTE
        with self.assertRaisesRegex(ValueError, 'Missing _PrelinkLinkKASLROffsets'):
            plan(self.native, bytes(classical), ['test.a'], SLIDE)


if __name__ == '__main__':
    unittest.main()
