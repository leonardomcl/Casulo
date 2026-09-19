#!/usr/bin/env python3
"""
casulo_detect_v2.py

Detector estático/heurístico para executáveis empacotados pelo Casulo,
com inventário de metadados PE/ELF.

Dependências opcionais recomendadas:
    pip install pefile pyelftools

Windows/PE:
- valida manifest RCDATA v1 e PackedRegion v4 quando possível;
- exibe ImageBase, EntryPoint RVA/VA, arquitetura, subsystem, ASLR/NX,
  relocations, TLS, imports, seções e VERSIONINFO.

Linux/ELF:
- procura PackedRegion v4 estruturalmente válido;
- exibe EntryPoint, base dos segmentos PT_LOAD, arquitetura, PIE,
  interpreter, DT_NEEDED e seções quando pyelftools está instalado.

Compressão:
- o formato Casulo v4 atual não grava um enum zstd/brotli autenticado no
  container. Portanto a identificação é heurística, baseada em imports e
  fingerprints textuais que possam ter sobrevivido ao build/link/strip.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import math
import os
import struct
import sys
from dataclasses import dataclass, asdict
from typing import Optional, Any

FRAG_FORMAT_VERSION = 4
FRAG_CHUNK_VERSION = 1
CHUNK_HEADER_SIZE = 88
DIR_ENTRY_SIZE = 16
FOOTER_SIZE = 40
TRAILER_SIZE = 32
TAG_SIZE = 32
IV_SIZE = 16
MANIFEST_HEADER_SIZE = 56
MANIFEST_ENTRY_SIZE = 16
MANIFEST_VERSION = 1
MAX_CHUNKS = 4096
MAX_PAYLOAD_SIZE = 512 * 1024 * 1024
MAX_PACKED_SIZE = MAX_PAYLOAD_SIZE + 64 * 1024 * 1024


@dataclass
class Detection:
    detected: bool
    confidence: str
    format: str
    method: str
    score: int
    region_start: Optional[int] = None
    region_end: Optional[int] = None
    footer_offset: Optional[int] = None
    footer_magic: Optional[str] = None
    chunk_count: Optional[int] = None
    final_size: Optional[int] = None
    manifest_resource_id: Optional[int] = None
    reasons: Optional[list[str]] = None


def u16(data: bytes, off: int, endian: str = '<') -> Optional[int]:
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from(endian + 'H', data, off)[0]


def u32(data: bytes, off: int, endian: str = '<') -> Optional[int]:
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from(endian + 'I', data, off)[0]


def u64(data: bytes, off: int, endian: str = '<') -> Optional[int]:
    if off < 0 or off + 8 > len(data):
        return None
    return struct.unpack_from(endian + 'Q', data, off)[0]


def safe_decode(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, bytes):
        for enc in ('utf-8', 'utf-16le', 'latin-1'):
            try:
                return value.decode(enc).rstrip('\x00')
            except Exception:
                pass
        return value.decode('latin-1', errors='replace').rstrip('\x00')
    return str(value)


def classify_file(data: bytes) -> str:
    if data.startswith(b'MZ'):
        return 'PE'
    if data.startswith(b'\x7fELF'):
        return 'ELF'
    return 'UNKNOWN'


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


def file_hashes(data: bytes) -> dict[str, str]:
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
    }


def machine_name_pe(machine: int) -> str:
    return {
        0x014C: 'x86',
        0x8664: 'x86-64',
        0x01C0: 'ARM',
        0x01C4: 'ARMv7',
        0xAA64: 'ARM64',
        0x0200: 'IA64',
    }.get(machine, f'0x{machine:04X}')


def subsystem_name(v: int) -> str:
    return {
        1: 'Native',
        2: 'Windows GUI',
        3: 'Windows Console',
        5: 'OS/2 Console',
        7: 'POSIX Console',
        9: 'Windows CE GUI',
        10: 'EFI Application',
        11: 'EFI Boot Service Driver',
        12: 'EFI Runtime Driver',
        13: 'EFI ROM',
        14: 'Xbox',
        16: 'Windows Boot Application',
    }.get(v, f'Unknown ({v})')


def parse_pe_version_info(pe) -> dict[str, str]:
    wanted = [
        'CompanyName', 'FileDescription', 'ProductName', 'LegalCopyright',
        'OriginalFilename', 'InternalName', 'ProductVersion', 'FileVersion',
        'Comments', 'LegalTrademarks', 'PrivateBuild', 'SpecialBuild',
    ]
    out: dict[str, str] = {}

    try:
        groups = getattr(pe, 'FileInfo', None) or []
        for group in groups:
            entries = group if isinstance(group, (list, tuple)) else [group]
            for entry in entries:
                key = safe_decode(getattr(entry, 'Key', b''))
                if key != 'StringFileInfo':
                    continue
                for st in getattr(entry, 'StringTable', []) or []:
                    for k, v in (getattr(st, 'entries', {}) or {}).items():
                        name = safe_decode(k)
                        value = safe_decode(v)
                        if value and name not in out:
                            out[name] = value
    except Exception:
        pass

    # FixedFileInfo é um fallback útil quando FileVersion/ProductVersion textual
    # não existe no recurso StringFileInfo.
    try:
        ffi = pe.VS_FIXEDFILEINFO[0]
        file_ver = (
            f'{ffi.FileVersionMS >> 16}.{ffi.FileVersionMS & 0xFFFF}.'
            f'{ffi.FileVersionLS >> 16}.{ffi.FileVersionLS & 0xFFFF}'
        )
        prod_ver = (
            f'{ffi.ProductVersionMS >> 16}.{ffi.ProductVersionMS & 0xFFFF}.'
            f'{ffi.ProductVersionLS >> 16}.{ffi.ProductVersionLS & 0xFFFF}'
        )
        out.setdefault('FileVersion', file_ver)
        out.setdefault('ProductVersion', prod_ver)
    except Exception:
        pass

    # Mantém primeiro os campos mais úteis e depois eventuais extras.
    ordered: dict[str, str] = {}
    for k in wanted:
        if out.get(k):
            ordered[k] = out[k]
    for k in sorted(out):
        if k not in ordered and out[k]:
            ordered[k] = out[k]
    return ordered


def inspect_pe(path: str, data: bytes) -> dict:
    info: dict[str, Any] = {
        'parser': 'basic',
        'format': 'PE',
    }

    # Fallback manual mínimo, caso pefile não esteja instalado.
    try:
        peoff = u32(data, 0x3C)
        if peoff is not None and data[peoff:peoff + 4] == b'PE\x00\x00':
            machine = u16(data, peoff + 4)
            sections = u16(data, peoff + 6)
            timestamp = u32(data, peoff + 8)
            opt_size = u16(data, peoff + 20)
            opt = peoff + 24
            magic = u16(data, opt)
            is64 = magic == 0x20B
            ep = u32(data, opt + 16)
            imagebase = u64(data, opt + 24) if is64 else u32(data, opt + 28)
            subsystem = u16(data, opt + (68 if is64 else 68))
            info.update({
                'architecture': machine_name_pe(machine or 0),
                'machine': f'0x{(machine or 0):04X}',
                'bits': 64 if is64 else 32,
                'number_of_sections': sections,
                'image_base': imagebase,
                'entry_point_rva': ep,
                'entry_point_va': (imagebase + ep) if imagebase is not None and ep is not None else None,
                'subsystem': subsystem_name(subsystem or 0),
                'timestamp_raw': timestamp,
                'optional_header_size': opt_size,
            })
    except Exception:
        pass

    try:
        import pefile  # type: ignore
    except ImportError:
        info['note'] = 'Instale pefile para VERSIONINFO/imports/seções detalhadas.'
        return info

    try:
        pe = pefile.PE(path, fast_load=False)
        info['parser'] = 'pefile'
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        ep_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        timestamp = int(pe.FILE_HEADER.TimeDateStamp)
        try:
            timestamp_iso = _dt.datetime.fromtimestamp(timestamp, tz=_dt.timezone.utc).isoformat()
        except Exception:
            timestamp_iso = None

        dll_char = int(pe.OPTIONAL_HEADER.DllCharacteristics)
        info.update({
            'architecture': machine_name_pe(int(pe.FILE_HEADER.Machine)),
            'machine': f'0x{int(pe.FILE_HEADER.Machine):04X}',
            'bits': 64 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 32,
            'image_base': image_base,
            'entry_point_rva': ep_rva,
            'entry_point_va': image_base + ep_rva,
            'subsystem': subsystem_name(int(pe.OPTIONAL_HEADER.Subsystem)),
            'number_of_sections': int(pe.FILE_HEADER.NumberOfSections),
            'size_of_image': int(pe.OPTIONAL_HEADER.SizeOfImage),
            'size_of_headers': int(pe.OPTIONAL_HEADER.SizeOfHeaders),
            'checksum': f'0x{int(pe.OPTIONAL_HEADER.CheckSum):08X}',
            'timestamp_raw': timestamp,
            'timestamp_utc': timestamp_iso,
            'linker_version': f'{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}',
            'aslr_dynamic_base': bool(dll_char & 0x0040),
            'high_entropy_va': bool(dll_char & 0x0020),
            'nx_compat': bool(dll_char & 0x0100),
            'cfg_guard_cf': bool(dll_char & 0x4000),
        })

        # Data directories.
        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        try:
            rel = dirs[5]
            info['relocations'] = {
                'present': bool(rel.VirtualAddress and rel.Size),
                'rva': int(rel.VirtualAddress),
                'size': int(rel.Size),
            }
        except Exception:
            pass
        try:
            tls = dirs[9]
            info['tls'] = {
                'present': bool(tls.VirtualAddress and tls.Size),
                'rva': int(tls.VirtualAddress),
                'size': int(tls.Size),
            }
        except Exception:
            pass
        try:
            sec = dirs[4]
            info['authenticode'] = {
                'present': bool(sec.VirtualAddress and sec.Size),
                'file_offset': int(sec.VirtualAddress),
                'size': int(sec.Size),
            }
        except Exception:
            pass

        sections = []
        end_of_sections = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
        for s in pe.sections:
            name = safe_decode(s.Name).rstrip('\x00')
            raw_off = int(s.PointerToRawData)
            raw_size = int(s.SizeOfRawData)
            end_of_sections = max(end_of_sections, raw_off + raw_size)
            try:
                ent = float(s.get_entropy())
            except Exception:
                ent = entropy(data[raw_off:raw_off + raw_size]) if raw_size else 0.0
            sections.append({
                'name': name,
                'rva': int(s.VirtualAddress),
                'virtual_size': int(s.Misc_VirtualSize),
                'raw_offset': raw_off,
                'raw_size': raw_size,
                'entropy': round(ent, 3),
                'characteristics': f'0x{int(s.Characteristics):08X}',
            })
        info['sections'] = sections
        info['overlay_size'] = max(0, len(data) - end_of_sections)

        imports = []
        try:
            for desc in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []) or []:
                dll = safe_decode(desc.dll)
                names = []
                for imp in desc.imports:
                    if imp.name:
                        names.append(safe_decode(imp.name))
                    elif imp.ordinal is not None:
                        names.append(f'ordinal:{imp.ordinal}')
                imports.append({'dll': dll, 'count': len(names), 'symbols': names})
        except Exception:
            pass
        info['imports'] = imports
        info['version_info'] = parse_pe_version_info(pe)

    except Exception as exc:
        info['pefile_error'] = str(exc)

    return info


def machine_name_elf(v: int) -> str:
    return {
        0x03: 'x86',
        0x3E: 'x86-64',
        0x28: 'ARM',
        0xB7: 'AArch64',
        0x08: 'MIPS',
        0xF3: 'RISC-V',
        0x15: 'PowerPC64',
    }.get(v, f'0x{v:04X}')


def inspect_elf(path: str, data: bytes) -> dict:
    info: dict[str, Any] = {'parser': 'basic', 'format': 'ELF'}
    if len(data) < 0x34 or not data.startswith(b'\x7fELF'):
        return info

    elf_class = data[4]
    elf_data = data[5]
    endian = '<' if elf_data == 1 else '>'
    bits = 64 if elf_class == 2 else 32

    try:
        e_type = u16(data, 16, endian)
        e_machine = u16(data, 18, endian)
        if bits == 64:
            entry = u64(data, 24, endian)
        else:
            entry = u32(data, 24, endian)
        info.update({
            'bits': bits,
            'endianness': 'little' if endian == '<' else 'big',
            'architecture': machine_name_elf(e_machine or 0),
            'machine': f'0x{(e_machine or 0):04X}',
            'elf_type': {1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE'}.get(e_type, str(e_type)),
            'pie': e_type == 3,
            'entry_point': entry,
        })
    except Exception:
        pass

    try:
        from elftools.elf.elffile import ELFFile  # type: ignore
    except ImportError:
        info['note'] = 'Instale pyelftools para segmentos, DT_NEEDED e seções detalhadas.'
        return info

    try:
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            info['parser'] = 'pyelftools'
            info['bits'] = elf.elfclass
            info['endianness'] = 'little' if elf.little_endian else 'big'
            info['entry_point'] = int(elf.header['e_entry'])
            info['elf_type'] = str(elf.header['e_type'])
            info['architecture'] = elf.get_machine_arch()

            load_vaddrs = []
            interp = None
            for seg in elf.iter_segments():
                if seg['p_type'] == 'PT_LOAD':
                    load_vaddrs.append(int(seg['p_vaddr']))
                elif seg['p_type'] == 'PT_INTERP':
                    try:
                        interp = seg.get_interp_name()
                    except Exception:
                        pass
            info['image_base'] = min(load_vaddrs) if load_vaddrs else None
            info['interpreter'] = interp
            info['pie'] = str(elf.header['e_type']) == 'ET_DYN'

            needed = []
            dyn = elf.get_section_by_name('.dynamic')
            if dyn is not None:
                for tag in dyn.iter_tags():
                    if tag.entry.d_tag == 'DT_NEEDED':
                        needed.append(tag.needed)
            info['needed_libraries'] = needed

            sections = []
            for s in elf.iter_sections():
                sections.append({
                    'name': s.name,
                    'address': int(s['sh_addr']),
                    'offset': int(s['sh_offset']),
                    'size': int(s['sh_size']),
                    'type': str(s['sh_type']),
                })
            info['sections'] = sections
    except Exception as exc:
        info['pyelftools_error'] = str(exc)

    return info


def guess_compression_mode(data: bytes, binary_info: dict) -> dict[str, Any]:
    """
    Heurística apenas. O PackedRegion v4 não carrega atualmente um identificador
    explícito de algoritmo, e a payload comprimida está cifrada.
    """
    low = data.lower()
    zstd_evidence: list[str] = []
    brotli_evidence: list[str] = []

    # Imports externos, caso alguma revisão use DLLs nativas.
    for item in binary_info.get('imports', []) or []:
        dll = str(item.get('dll', '')).lower()
        if 'zstd' in dll:
            zstd_evidence.append(f'import {dll}')
        if 'brotli' in dll:
            brotli_evidence.append(f'import {dll}')

    for lib in binary_info.get('needed_libraries', []) or []:
        name = str(lib).lower()
        if 'zstd' in name:
            zstd_evidence.append(f'DT_NEEDED {name}')
        if 'brotli' in name:
            brotli_evidence.append(f'DT_NEEDED {name}')

    # Fingerprints textuais de crates/implementações. Podem desaparecer com strip/LTO.
    zstd_tokens = [b'ruzstd', b'framedecoder', b'zstd']
    brotli_tokens = [b'brotli_decompressor', b'brotlidecompressor', b'brotli']

    for t in zstd_tokens:
        if t in low:
            zstd_evidence.append(f'string {t.decode(errors="ignore")}')
    for t in brotli_tokens:
        if t in low:
            brotli_evidence.append(f'string {t.decode(errors="ignore")}')

    # Remove duplicatas preservando ordem.
    zstd_evidence = list(dict.fromkeys(zstd_evidence))
    brotli_evidence = list(dict.fromkeys(brotli_evidence))

    if zstd_evidence and not brotli_evidence:
        return {'mode': 'zstd', 'confidence': 'heurística', 'evidence': zstd_evidence}
    if brotli_evidence and not zstd_evidence:
        return {'mode': 'brotli', 'confidence': 'heurística', 'evidence': brotli_evidence}
    if zstd_evidence and brotli_evidence:
        return {
            'mode': 'ambíguo',
            'confidence': 'baixa',
            'evidence': zstd_evidence + brotli_evidence,
            'note': 'foram encontrados fingerprints dos dois algoritmos',
        }
    return {
        'mode': 'indeterminado',
        'confidence': 'não disponível estaticamente',
        'evidence': [],
        'note': 'a payload comprimida está cifrada e o formato v4 não grava um enum do algoritmo',
    }


def validate_packed_region(blob: bytes, footer_pos: int, *, absolute_base: int = 0,
                           expected_magic_bytes: Optional[bytes] = None) -> Optional[Detection]:
    if footer_pos < 0 or footer_pos + FOOTER_SIZE + TRAILER_SIZE > len(blob):
        return None

    magic = u64(blob, footer_pos)
    version = u32(blob, footer_pos + 8)
    count = u32(blob, footer_pos + 12)
    dir_size = u64(blob, footer_pos + 16)
    packed_size = u64(blob, footer_pos + 24)
    final_size = u64(blob, footer_pos + 32)

    if None in (magic, version, count, dir_size, packed_size, final_size):
        return None
    if version != FRAG_FORMAT_VERSION:
        return None
    if count == 0 or count > MAX_CHUNKS:
        return None
    if dir_size != count * DIR_ENTRY_SIZE:
        return None
    if packed_size == 0 or packed_size > MAX_PACKED_SIZE:
        return None
    if final_size == 0 or final_size > MAX_PAYLOAD_SIZE:
        return None

    region_end = footer_pos + FOOTER_SIZE + TRAILER_SIZE
    region_start = region_end - packed_size
    if region_start < 0:
        return None
    if region_start + packed_size - FOOTER_SIZE - TRAILER_SIZE != footer_pos:
        return None

    dir_pos = footer_pos - dir_size
    if dir_pos < region_start:
        return None

    chunk_region_size = dir_pos - region_start
    if chunk_region_size <= 0:
        return None

    expected_off = 0
    reasons = [
        'footer v4 coerente',
        'dir_size == chunk_count * 16',
        'packed_size aponta para o início exato da região',
    ]

    for i in range(count):
        ent = dir_pos + i * DIR_ENTRY_SIZE
        ch_off = u64(blob, ent)
        ch_size = u64(blob, ent + 8)
        if ch_off is None or ch_size is None:
            return None
        if ch_off != expected_off:
            return None
        if ch_size < CHUNK_HEADER_SIZE + TAG_SIZE + IV_SIZE:
            return None

        ch_start = region_start + ch_off
        ch_end = ch_start + ch_size
        if ch_start < region_start or ch_end > dir_pos:
            return None

        if blob[ch_start] != FRAG_CHUNK_VERSION:
            return None
        if blob[ch_start + 1:ch_start + 4] != b'\x00\x00\x00':
            return None
        if u32(blob, ch_start + 4) != i:
            return None

        cipher_len = u64(blob, ch_start + 72)
        plain_len = u64(blob, ch_start + 80)
        if cipher_len is None or plain_len is None:
            return None
        if cipher_len == 0 or cipher_len % IV_SIZE != 0:
            return None
        if plain_len == 0 or plain_len > cipher_len:
            return None
        if CHUNK_HEADER_SIZE + cipher_len + TAG_SIZE != ch_size:
            return None
        expected_off += ch_size

    if expected_off != chunk_region_size:
        return None

    magic_bytes = struct.pack('<Q', magic)
    if expected_magic_bytes is not None:
        if magic_bytes != expected_magic_bytes:
            return None
        reasons.append('magic do manifest coincide com FooterMagic')

    reasons.extend([
        'offsets dos chunks são contíguos',
        'todos os chunks têm cabeçalho v4 coerente',
        'cipher_len é múltiplo de 16 e bate com o tamanho físico',
    ])

    score = 100 if expected_magic_bytes is not None else 90
    return Detection(
        detected=True,
        confidence='muito alta' if score == 100 else 'alta',
        format='Casulo PackedRegion v4',
        method='validação estrutural',
        score=score,
        region_start=absolute_base + region_start,
        region_end=absolute_base + region_end,
        footer_offset=absolute_base + footer_pos,
        footer_magic=f'0x{magic:016X}',
        chunk_count=count,
        final_size=final_size,
        reasons=reasons,
    )


def scan_v4_regions(data: bytes) -> list[Detection]:
    results: list[Detection] = []
    needle = struct.pack('<I', FRAG_FORMAT_VERSION)
    pos = 0
    seen = set()
    while True:
        hit = data.find(needle, pos)
        if hit < 0:
            break
        pos = hit + 1
        footer_pos = hit - 8
        if footer_pos < 0 or footer_pos in seen:
            continue
        seen.add(footer_pos)
        det = validate_packed_region(data, footer_pos)
        if det is not None:
            results.append(det)
    return results


def extract_pe_rcdata(path: str) -> Optional[dict[int, bytes]]:
    try:
        import pefile  # type: ignore
    except ImportError:
        return None

    try:
        pe = pefile.PE(path, fast_load=False)
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return {}

        image = pe.get_memory_mapped_image()
        result: dict[int, bytes] = {}
        for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if type_entry.id != 10:
                continue
            for name_entry in type_entry.directory.entries:
                res_id = name_entry.id
                if res_id is None:
                    continue
                for lang_entry in name_entry.directory.entries:
                    e = lang_entry.data.struct
                    result[int(res_id)] = bytes(image[e.OffsetToData:e.OffsetToData + e.Size])
                    break
        return result
    except Exception:
        return {}


def validate_manifest_resources(resources: dict[int, bytes]) -> list[Detection]:
    detections: list[Detection] = []

    for manifest_id, manifest in resources.items():
        if len(manifest) < MANIFEST_HEADER_SIZE:
            continue
        version = u32(manifest, 8)
        count = u32(manifest, 12)
        total_size = u64(manifest, 16)
        if version != MANIFEST_VERSION:
            continue
        if count is None or count == 0 or count > MAX_CHUNKS:
            continue
        if total_size is None or total_size == 0 or total_size > MAX_PACKED_SIZE:
            continue
        if len(manifest) != MANIFEST_HEADER_SIZE + count * MANIFEST_ENTRY_SIZE:
            continue

        manifest_magic = manifest[0:8]
        expected_hash = manifest[24:56]
        ids: set[int] = set()
        packed = bytearray()
        total_seen = 0
        ok = True

        for i in range(count):
            ent = MANIFEST_HEADER_SIZE + i * MANIFEST_ENTRY_SIZE
            logical_index = u32(manifest, ent)
            resource_id = u16(manifest, ent + 4)
            reserved = u16(manifest, ent + 6)
            frag_size = u64(manifest, ent + 8)

            if None in (logical_index, resource_id, reserved, frag_size):
                ok = False
                break
            if logical_index != i or resource_id == 0 or resource_id == manifest_id:
                ok = False
                break
            if reserved != 0 or frag_size == 0 or resource_id in ids:
                ok = False
                break

            fragment = resources.get(resource_id)
            if fragment is None or len(fragment) != frag_size:
                ok = False
                break

            ids.add(resource_id)
            packed.extend(fragment)
            total_seen += frag_size
            if total_seen > total_size:
                ok = False
                break

        if not ok or total_seen != total_size or len(packed) != total_size:
            continue
        if hashlib.sha256(packed).digest() != expected_hash:
            continue
        if len(packed) < FOOTER_SIZE + TRAILER_SIZE:
            continue

        footer_pos = len(packed) - FOOTER_SIZE - TRAILER_SIZE
        det = validate_packed_region(bytes(packed), footer_pos,
                                     expected_magic_bytes=manifest_magic)
        if det is None:
            continue

        det.method = 'PE RCDATA manifest v1 + PackedRegion v4'
        det.format = 'Casulo Windows'
        det.manifest_resource_id = manifest_id
        det.score = 100
        det.confidence = 'muito alta'
        det.reasons = [
            'manifest RCDATA v1 estruturalmente válido',
            'IDs e tamanhos dos fragmentos são coerentes',
            'SHA-256 do PackedRegion recomposto confere',
            'manifest magic == FooterMagic.to_le_bytes()',
        ] + (det.reasons or [])
        detections.append(det)

    return detections


def detect(path: str) -> dict:
    with open(path, 'rb') as f:
        data = f.read()

    file_type = classify_file(data)
    binary_info: dict[str, Any]
    if file_type == 'PE':
        binary_info = inspect_pe(path, data)
    elif file_type == 'ELF':
        binary_info = inspect_elf(path, data)
    else:
        binary_info = {'parser': 'none', 'format': file_type}

    output = {
        'file': os.path.abspath(path),
        'file_type': file_type,
        'size': len(data),
        'entropy': round(entropy(data), 3),
        'hashes': file_hashes(data),
        'binary_info': binary_info,
        'compression': guess_compression_mode(data, binary_info),
        'detected': False,
        'best': None,
        'detections': [],
        'notes': [],
    }

    detections: list[Detection] = []
    if file_type == 'PE':
        resources = extract_pe_rcdata(path)
        if resources is None:
            output['notes'].append(
                'pefile não instalado: análise de RCDATA não executada; usando fallback estrutural.'
            )
        elif resources:
            detections.extend(validate_manifest_resources(resources))
        else:
            output['notes'].append('Nenhum RT_RCDATA utilizável encontrado.')

    detections.extend(scan_v4_regions(data))

    unique = {}
    for d in detections:
        key = (d.region_start, d.region_end, d.footer_magic, d.chunk_count)
        old = unique.get(key)
        if old is None or d.score > old.score:
            unique[key] = d

    detections = sorted(unique.values(), key=lambda x: x.score, reverse=True)
    if detections:
        output['detected'] = True
        output['best'] = asdict(detections[0])
        output['detections'] = [asdict(x) for x in detections]
    else:
        output['notes'].append('Nenhuma estrutura Casulo v4 válida foi encontrada.')
        if file_type == 'ELF':
            output['notes'].append(
                'Se o Stub Linux atual usa um container diferente do PackedRegion v4, '
                'é preciso adicionar o layout específico dessa revisão.'
            )

    return output


def hx(v: Any) -> str:
    return f'0x{v:X}' if isinstance(v, int) else '-'


def print_binary_info(result: dict) -> None:
    info = result.get('binary_info') or {}
    print('\n=== Informações do binário ===')
    print(f"Formato:       {result.get('file_type')}")
    if info.get('architecture'):
        print(f"Arquitetura:   {info['architecture']} ({info.get('bits', '?')}-bit)")

    if result.get('file_type') == 'PE':
        if info.get('image_base') is not None:
            print(f"ImageBase:     {hx(info['image_base'])}")
        if info.get('entry_point_rva') is not None:
            print(f"EntryPoint:    RVA {hx(info['entry_point_rva'])} / VA {hx(info.get('entry_point_va'))}")
        if info.get('subsystem'):
            print(f"Subsystem:     {info['subsystem']}")
        if info.get('size_of_image') is not None:
            print(f"SizeOfImage:   {info['size_of_image']} bytes ({hx(info['size_of_image'])})")
        if info.get('timestamp_utc'):
            print(f"Timestamp:     {info['timestamp_utc']}")
        if info.get('linker_version'):
            print(f"Linker:        {info['linker_version']}")
        print(f"ASLR:          {'sim' if info.get('aslr_dynamic_base') else 'não'}")
        print(f"NX/DEP:        {'sim' if info.get('nx_compat') else 'não'}")
        if 'high_entropy_va' in info:
            print(f"HighEntropyVA: {'sim' if info.get('high_entropy_va') else 'não'}")
        rel = info.get('relocations') or {}
        if rel:
            print(f"Relocations:   {'sim' if rel.get('present') else 'não'} (RVA {hx(rel.get('rva'))}, {rel.get('size', 0)} bytes)")
        tls = info.get('tls') or {}
        if tls:
            print(f"TLS directory: {'sim' if tls.get('present') else 'não'} (RVA {hx(tls.get('rva'))}, {tls.get('size', 0)} bytes)")
        auth = info.get('authenticode') or {}
        if auth:
            print(f"Authenticode:  {'presente' if auth.get('present') else 'ausente'}")
        if info.get('overlay_size') is not None:
            print(f"Overlay:       {info['overlay_size']} bytes")

    elif result.get('file_type') == 'ELF':
        if info.get('image_base') is not None:
            print(f"ImageBase:     {hx(info['image_base'])} (menor PT_LOAD)")
        if info.get('entry_point') is not None:
            print(f"EntryPoint:    {hx(info['entry_point'])}")
        if info.get('elf_type'):
            print(f"ELF Type:      {info['elf_type']}")
        if 'pie' in info:
            print(f"PIE:           {'sim' if info.get('pie') else 'não'}")
        if info.get('interpreter'):
            print(f"Interpreter:   {info['interpreter']}")

    comp = result.get('compression') or {}
    print(f"Compressão:    {comp.get('mode', 'indeterminado')} ({comp.get('confidence', 'n/d')})")
    for ev in comp.get('evidence') or []:
        print(f"  evidência:   {ev}")

    print(f"Tamanho:       {result.get('size')} bytes")
    print(f"Entropia:      {result.get('entropy')} bits/byte")
    hashes = result.get('hashes') or {}
    if hashes:
        print(f"MD5:           {hashes.get('md5', '')}")
        print(f"SHA1:          {hashes.get('sha1', '')}")
        print(f"SHA256:        {hashes.get('sha256', '')}")

    vi = info.get('version_info') or {}
    if vi:
        print('\n=== VERSIONINFO ===')
        preferred = [
            'CompanyName', 'FileDescription', 'ProductName', 'LegalCopyright',
            'OriginalFilename', 'InternalName', 'ProductVersion', 'FileVersion',
        ]
        for key in preferred:
            if vi.get(key):
                print(f'{key + ":":18} {vi[key]}')
        extras = [k for k in vi if k not in preferred]
        for key in extras:
            print(f'{key + ":":18} {vi[key]}')

    imports = info.get('imports') or []
    if imports:
        print('\n=== Imports ===')
        for imp in imports:
            print(f"{imp.get('dll')}: {imp.get('count', 0)} símbolo(s)")

    needed = info.get('needed_libraries') or []
    if needed:
        print('\n=== DT_NEEDED ===')
        for lib in needed:
            print(lib)

    sections = info.get('sections') or []
    if sections:
        print('\n=== Seções ===')
        if result.get('file_type') == 'PE':
            print(f"{'Nome':10} {'RVA':>12} {'Virtual':>10} {'Raw':>10} {'Entropia':>9}")
            for s in sections:
                print(f"{s.get('name','')[:10]:10} {hx(s.get('rva')):>12} {s.get('virtual_size',0):10} {s.get('raw_size',0):10} {s.get('entropy',0):9.3f}")
        else:
            print(f"{'Nome':18} {'Address':>14} {'Offset':>12} {'Size':>12}")
            for s in sections:
                print(f"{s.get('name','')[:18]:18} {hx(s.get('address')):>14} {hx(s.get('offset')):>12} {s.get('size',0):12}")

    if info.get('note'):
        print(f"\nNota parser: {info['note']}")


def print_human(result: dict) -> None:
    print(f"Arquivo: {result['file']}")
    print_binary_info(result)

    if not result['detected']:
        print('\n=== Detecção Casulo ===')
        print('Resultado: NÃO detectado como Casulo v4')
        for note in result.get('notes', []):
            print(f'  - {note}')
        return

    best = result['best']
    print('\n=== Detecção Casulo ===')
    print('Resultado: CASULO detectado')
    print(f"Confiança:   {best['confidence']}")
    print(f"Score:       {best['score']}/100")
    print(f"Método:      {best['method']}")
    if best.get('footer_magic'):
        print(f"FooterMagic: {best['footer_magic']}")
    if best.get('chunk_count') is not None:
        print(f"Chunks:      {best['chunk_count']}")
    if best.get('final_size') is not None:
        print(f"Payload:     {best['final_size']} bytes")
    if best.get('region_start') is not None:
        print(f"Região:      0x{best['region_start']:X} .. 0x{best['region_end']:X}")
    if best.get('manifest_resource_id') is not None:
        print(f"Manifest ID: {best['manifest_resource_id']}")

    print('\nEvidências:')
    for reason in best.get('reasons') or []:
        print(f'  + {reason}')

    for note in result.get('notes', []):
        print(f'\nNota: {note}')


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Detector estático de executáveis empacotados pelo Casulo + metadados PE/ELF.'
    )
    parser.add_argument('binary', help='Executável PE/ELF a analisar')
    parser.add_argument('--json', action='store_true', help='Emite o resultado completo em JSON')
    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        print(f'Erro: arquivo não encontrado: {args.binary}', file=sys.stderr)
        return 2

    try:
        result = detect(args.binary)
    except (OSError, ValueError) as exc:
        print(f'Erro ao analisar arquivo: {exc}', file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_human(result)

    return 0 if result['detected'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
