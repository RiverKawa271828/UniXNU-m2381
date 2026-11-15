#!/usr/bin/env python3
"""Compile the m2381 hardware DTS and pin the Adreno 740 resources the GPU lane consumes.

The m2381 fork of sheng's audit-adreno-platform.py: sheng compiles a full mainline
board DTS from .cache/linux-dts; this board owns its DTS (device:dts/m2381.dts over
the pinned sm8550.dtsi) and the GPU/OPP/ZAP/command-DB values come from the stock FDT
translation recorded in scripts/data/adreno-board-m2381.json. The script refuses any
drift between the compiled DTB and those pins and writes
build/adreno-firmware/m2381-platform.json for the prepare-* recipes.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEVICE = Path(os.environ.get('UNIXNU_DEVICE') or ROOT.parent / 'UniXNU-m2381')
PINS = json.loads((ROOT / 'scripts/data/adreno-board-m2381.json').read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(value, message):
    if not value:
        sys.exit(message)


def run(command, **kw):
    return subprocess.check_output([str(c) for c in command], text=True, **kw)


for relative, expected in ((PINS['board']['dts'], PINS['board']['dts_sha256']),
                           (PINS['board']['dtsi'], PINS['board']['dtsi_sha256'])):
    path = DEVICE / relative
    require(path.is_file() and sha(path) == expected, 'Pinned board source differs: ' + relative)

output = ROOT / 'build/adreno-firmware'
output.mkdir(parents=True, exist_ok=True)
dtb = output / 'm2381.dtb'
command = ['dtc', '-I', 'dts', '-O', 'dtb', '-o', dtb,
           '-i', DEVICE / 'soc/sm8550/dts', '-i', DEVICE / 'dts']
with (output / 'dtc.log').open('w') as log:
    subprocess.run([str(c) for c in command + [DEVICE / PINS['board']['dts']]], stderr=log, check=True)


def prop(node, name, kind='x'):
    return run(['fdtget', '-t', kind, dtb, node, name]).strip()


def cells(node, name):
    return [int(word, 16) for word in prop(node, name).split()]


def optional(node, name, kind='x'):
    result = subprocess.run(['fdtget', '-t', kind, dtb, node, name], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


nodes = dict(gpu='/soc/gpu@3d00000', gmu='/soc/gmu@3d6a000', smmu='/soc/iommu@3da0000')
resources = {}
for name, node in nodes.items():
    values = cells(node, 'reg')
    require(len(values) % 4 == 0, 'Require 64-bit address/size register ranges')
    ranges = [dict(base=(values[i] << 32) | values[i + 1], bytes=(values[i + 2] << 32) | values[i + 3])
              for i in range(0, len(values), 4)]
    resources[name] = dict(node=node, compatible=prop(node, 'compatible', 's'), ranges=ranges,
                           status=prop(node, 'status', 's') if optional(node, 'status', 's') else 'okay')
require(resources['gpu']['status'] == 'okay' and
        resources['gpu']['compatible'] == 'qcom,adreno-43050a01 qcom,adreno' and
        resources['gmu']['status'] == 'okay' and
        resources['gmu']['compatible'] == 'qcom,adreno-gmu-740.1 qcom,adreno-gmu' and
        resources['smmu']['status'] == 'okay', 'Pinned enabled GPU/GMU/SMMU identity')

gpu_names = prop(nodes['gpu'], 'reg-names', 's').split()
gmu_names = prop(nodes['gmu'], 'reg-names', 's').split()
require(gpu_names == ['kgsl_3d0_reg_memory', 'cx_mem', 'cx_dbgc'], 'GPU register-name binding differs')
require(gmu_names == ['gmu', 'rscc', 'gmu_pdc'], 'GMU register-name binding differs (upstream layout)')
smmu = cells(nodes['smmu'], 'phandle')[0]
require(cells(nodes['gpu'], 'iommus') == [smmu, 0, 0, smmu, 1, 0] and
        cells(nodes['gmu'], 'iommus') == [smmu, 5, 0],
        'Exact GPU streams 0/1 and GMU stream 5 must bind the same Adreno SMMU')

# OPP tables: the stock pwrlevels translated to operating-points-v2, pinned exactly.
def read_opps(node, gpu):
    table = node + '/opp-table'
    require(cells(node, 'operating-points-v2') == cells(table, 'phandle'), 'OPP phandle binding mismatch: ' + node)
    entries = []
    for child in run(['fdtget', '-l', dtb, table]).split():
        path = table + '/' + child
        keys = set(run(['fdtget', '-p', dtb, path]).split())
        supported = {'opp-hz', 'opp-level', 'opp-peak-kBps', 'qcom,opp-acd-level', 'phandle', 'status'}
        require(not keys - supported, 'Unimplemented OPP property ' + repr(keys - supported) + ' at ' + path)
        if 'status' in keys and prop(path, 'status', 's') != 'okay':
            continue
        hz = cells(path, 'opp-hz')
        require(len(hz) == 2, 'Expected 64-bit opp-hz at ' + path)
        entry = dict(hz=(hz[0] << 32) | hz[1], level=cells(path, 'opp-level')[0])
        if gpu:
            entry['kbps'] = cells(path, 'opp-peak-kBps')[0]
            entry['acd'] = cells(path, 'qcom,opp-acd-level')[0]
        entries.append(entry)
    entries.sort(key=lambda e: e['hz'])
    return entries

gpu_opps = read_opps(nodes['gpu'], True)
gmu_opps = read_opps(nodes['gmu'], False)
expected_gpu = sorted((dict(hz=e['hz'], level=e['level'], kbps=e['kbps'], acd=int(e['acd'], 16))
                       for e in PINS['gpu_opps']), key=lambda e: e['hz'])
expected_gmu = sorted((dict(hz=e['hz'], level=e['level']) for e in PINS['gmu_opps']), key=lambda e: e['hz'])
require(gpu_opps == expected_gpu, 'GPU OPP table differs from the pinned stock translation')
require(gmu_opps == expected_gmu, 'GMU OPP table differs from the pinned stock translation')

zap = nodes['gpu'] + '/zap-shader'
require(prop(zap, 'firmware-name', 's') == PINS['board']['zap_firmware_name'], 'Real board-specific ZAP input')
reservation = PINS['board']['gpu_micro_code']['node']
require(cells(reservation, 'phandle') == cells(zap, 'memory-region') and
        cells(reservation, 'reg') == [0, int(PINS['board']['gpu_micro_code']['base'], 16), 0,
                                      int(PINS['board']['gpu_micro_code']['bytes'], 16)],
        'ZAP reservation binding')
subprocess.run(['fdtget', dtb, reservation, 'no-map'], capture_output=True, check=True)
db_node = PINS['board']['command_db']['node']
require(prop(db_node, 'compatible', 's') == PINS['board']['command_db']['compatible'], 'Command DB binding mismatch')
require(cells(db_node, 'reg') == [0, int(PINS['board']['command_db']['base'], 16), 0,
                                  int(PINS['board']['command_db']['bytes'], 16)], 'Command DB range mismatch')
subprocess.run(['fdtget', dtb, db_node, 'no-map'], capture_output=True, check=True)

(output / 'm2381-platform.json').write_text(json.dumps(dict(
    board='m2381', compiled_dtb_sha256=sha(dtb), resources=resources,
    gpu_streams=[0, 1], gmu_stream=5, gpu_opps=gpu_opps, gmu_opps=gmu_opps,
    zap_reserved_bytes=PINS['board']['gpu_micro_code']['bytes'],
    command_db=PINS['board']['command_db'],
    static_only=True, hardware_registers_observed=False, smmu_page_geometry_qualified=False,
    gmu_started=False, gpu_submission_qualified=False, metal_qualified=False), indent=2) + '\n')
print('PASS: pinned enabled A740 identity, GPU/GMU/SMMU resources, OPP tables, exact stream bindings, '
      'ZAP and command-DB reservations; source evidence only')
