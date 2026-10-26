#!/usr/bin/env python3
"""Parse the m2381 UFS diagnostic log window (kits/sheng BootLog.c, sheng-log=1).

The writer puts, every 2 s, one text slot (the full diagnostic page, the
banner, the exec census, the probe sections), then the kernel message buffer,
then the header that makes both visible — into the last 32 MiB of userdata
(block 0 = header, blocks 1..32 = msgbuf, blocks 33.. = slots of 16 blocks in
a ring; ~509 slots ≈ 17 minutes before the ring wraps). The window survives
power-off, so a run can be read back afterwards: boot the nura-min Linux
image (USB NCM), dd the tail of the userdata partition over, and feed the raw
image to this tool.

On the device (userdata = sda22, 512-byte sectors): the window is the last
65536 sectors of the partition, e.g.
    dd if=/dev/block/sda2x of=/tmp/logwindow.img bs=512 skip=$((PART_SECTORS-65536)) count=65536
(PART_SECTORS = the partition's size in sysfs; 2330472*8+972326040 in the
first_data_lba terms of board.toml — read /sys/class/block/sda2x/size instead).
Then fetch /tmp/logwindow.img over the NCM network (devpull) and run:

    ./read-m2381-ufs-log.py logwindow.img [--page] [--spawn] [--msg] [--all]

default: the text slots in chronological order; --page only the [page]
diagnostic snapshots (the pacing timeline: stage +age, spawn=, EXIT, UFS TIME),
--spawn only the census sections, --msg the message buffer, --all everything.
"""
import argparse
import struct
import sys

BLOCK = 4096
MSG_FIRST, MSG_BLOCKS = 1, 32
SLOT_FIRST, SLOT_BLOCKS = 33, 16


def parse_header(data):
    magic = data[0:8]
    if magic != b"SHLOG001":
        sys.exit(f"not a boot log window (magic {magic!r})")
    (version, header_bytes, boot_id, first_lba, window_blocks, msg_first, msg_blocks,
     msg_bytes, slot_first, slot_blocks, slot_count, slots_written,
     uptime_s, rounds, write_errors, gpt_open, gpt_last, state) = struct.unpack_from(
        "<IIQQIIIIIIIIIIIII I".replace(" ", ""), data, 8)
    tag = data[88:120].split(b"\0")[0].decode("ascii", "replace")
    (export_first, export_blocks, export_bytes, export_generation, export_below,
     diag_first, diag_bytes) = struct.unpack_from("<7I", data, 120)
    return dict(version=version, boot_id=boot_id, first_lba=first_lba,
                window_blocks=window_blocks, msg_bytes=msg_bytes,
                slot_first=slot_first, slot_blocks=slot_blocks,
                slot_count=slot_count, slots_written=slots_written,
                uptime_s=uptime_s, rounds=rounds, write_errors=write_errors,
                gpt_open=gpt_open, gpt_last=gpt_last, state=state, tag=tag,
                export_bytes=export_bytes, diag_bytes=diag_bytes)


def slot_round(text):
    # "#slot %u t=%us tag=%s"
    for line in text.split("\n"):
        if line.startswith("#slot "):
            return int(line.split()[1])
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("image", help="raw dd image of the 32 MiB log window")
    ap.add_argument("--page", action="store_true", help="only the [page] diagnostic snapshots")
    ap.add_argument("--spawn", action="store_true", help="only the [spawn] census sections")
    ap.add_argument("--msg", action="store_true", help="the kernel message buffer")
    ap.add_argument("--all", action="store_true", help="everything (slots + msgbuf)")
    args = ap.parse_args()

    data = open(args.image, "rb").read()
    h = parse_header(data)
    shown = (f"tag={h['tag']} version={h['version']} rounds={h['rounds']} "
             f"slots_written={h['slots_written']}/{h['slot_count']} uptime={h['uptime_s']}s "
             f"write_errors={h['write_errors']} gpt {h['gpt_open']}->{h['gpt_last']} "
             f"state={h['state']} export_bytes={h['export_bytes']}")
    print(f"# log window: {shown}", file=sys.stderr)

    if args.msg:
        raw = data[MSG_FIRST * BLOCK:(MSG_FIRST + MSG_BLOCKS) * BLOCK]
        sys.stdout.write(raw[:h["msg_bytes"]].decode("ascii", "replace"))
        return
    if not args.page and not args.spawn and not args.all:
        args.all = True  # default: every slot, chronological

    slots = []
    for index in range(h["slot_count"]):
        at = (h["slot_first"] + index * h["slot_blocks"]) * BLOCK
        raw = data[at:at + h["slot_blocks"] * BLOCK]
        text = raw.decode("ascii", "replace")
        if not text.startswith("#slot "):
            continue
        text = text.rstrip("\0")
        round_no = slot_round(text)
        if round_no is None:
            continue
        if args.page:
            text = extract_section(text, "[page]", "[banner]")
        elif args.spawn:
            text = extract_section(text, "[spawn]")
        if text.strip():
            slots.append((round_no, text))
    slots.sort()
    for _, text in slots:
        sys.stdout.write(text + "\n")


def extract_section(text, start, stop=None):
    lines, keep, out = text.split("\n"), False, []
    for line in lines:
        if line.startswith("#slot "):
            out.append(line)
        elif line == start:
            keep = True
        elif stop and line == stop:
            keep = False
        elif keep and not line.startswith("["):
            out.append(line)
        elif keep and line.startswith("["):
            break
    return "\n".join(out)


if __name__ == "__main__":
    main()
