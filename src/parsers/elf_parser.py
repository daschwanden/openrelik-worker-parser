# -*- coding: utf-8 -*-
# Copyright 2025 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Parse ELF files."""

import json
import lief
import os
import time
import tlsh

from .hashers import entropy
from .hashers import md5
from .hashers import sha256

from typing import List

from openrelik_worker_common.reporting import Report, Priority


class Hashes(object):

  def __init__(self):
    self.sha256 = ""
    self.md5 = ""
    self.ssdeep = ""
    self.tlsh = ""


class Section(object):

  def __init__(self):
    self.name = ""
    self.type = ""
    self.virtual_address = 0
    self.file_offset = 0
    self.flags = []
    self.size = 0
    self.entropy = 0


class Segment(object):

  def __init__(self, sections: List[Section]):
    self.type = ""
    self.flags = ""
    self.file_offset = 0
    self.virtual_size = 0
    self.physical_size = 0
    self.sections = sections


class Symbol(object):

  def __init__(self):
    self.name = ""
    self.type = ""
    self.version = ""
    self.value = ""
    self.visibility = ""
    self.binding = ""


class Library(object):

  def __init__(self):
    self.name = ""


class ParsedHeader(object):

  def __init__(self):
    self.entrypoint = 0
    self.file_type = ""
    self.header_size = 0
    self.identity_abi_version = 0
    self.identity_class = ""
    self.identity_data = ""
    self.identity_os_abi = ""
    self.identity_version = ""
    self.numberof_sections = 0
    self.numberof_segments = 0
    self.machine_type = ""
    self.object_file_version = ""
    self.processor_flags = ""
    self.program_header_offset = 0
    self.program_header_size = 0
    self.section_header_offset = 0
    self.section_header_size = 0


class ParsedElf(object):

  def __init__(
      self, hashes: Hashes, header: ParsedHeader, segments: List[Segment],
      imp_symbols: List[Symbol], exp_symbols: List[Symbol],
      dyn_symbols: List[Symbol], tab_symbols: List[Symbol],
      libaries: List[Library]):
    self.request = ""
    self.workflow_id = ""
    self.file_name = ""
    self.processing_time = 0
    self.virtual_size = 0
    self.hashes = hashes
    self.header = header
    self.segments = segments
    self.imported_symbols = imp_symbols
    self.exported_symbols = exp_symbols
    self.dynamic_symbols = dyn_symbols
    self.symtab_symbols = tab_symbols
    self.libaries = libaries


def GetDigest(hasher, data):
  """Executes a hasher and returns the digest.
  Args:
    hasher (BaseHasher): hasher to execute.
    data (bytestring) : data to be hashed.
  Returns:
    digest (str): digest returned by hasher.
  """
  hasher.Update(data)
  return hasher.GetStringDigest()


def GetHashes(elf_fd, binary):
  """Parses a ELF binary.
  Args:
    elf_fd (int): file descriptor to the binary.
    binary (lief.ELF.Binary): binary to compute the hashes on.
  Returns:
    Hashes: the computed hashes.
  """
  binary_size = binary.virtual_size
  elf_fd.seek(0)
  data = elf_fd.read(binary_size)
  hashes = Hashes()
  hashes.md5 = GetDigest(md5.MD5Hasher(), data)
  hashes.sha256 = GetDigest(sha256.SHA256Hasher(), data)
  hashes.tlsh = tlsh.hash(data)
  #hashes.ssdeep = pyssdeep.get_hash_buffer(data)
  return hashes


def GetSections(segment):
  """Retrieves the sections of a ELF binary segment.
  Args:
    segment (lief.ELF.Binary.Segment): segment to extract the sections from.
  Returns:
    Sections: the extracted sections.
  """
  sects = segment.sections
  sections = []
  if len(sects) > 0:
    for sect in sects:
      section = Section()
      section.name = sect.name
      section.type = str(sect.type).split(".")[-1]
      section.virtual_address = sect.virtual_address
      section.file_offset = sect.file_offset
      section.size = sect.size
      section.entropy = abs(sect.entropy)
      for flag in sect.flags_list:
        section.flags.append(str(flag).split(".")[-1])
      sections.append(section)
  return sections

def GetSegments(binary):
  """Retrieves the segments of a ELF binary.
  Args:
    binary (lief.ELF.Binary): binary to extract the segments from.
  Returns:
    Segments: the extracted segments.
  """
  segments = []
  sgmts = binary.segments
  if len(sgmts) > 0:
    for sgmt in sgmts:
      segment = Segment(GetSections(sgmt))
      flags_str = ["-"] * 3
      if lief.ELF.Segment.FLAGS.R in sgmt:
        flags_str[0] = "r"
      if lief.ELF.Segment.FLAGS.W in sgmt:
        flags_str[1] = "w"
      if lief.ELF.Segment.FLAGS.X in sgmt:
        flags_str[2] = "x"
      segment.flags = "".join(flags_str)
      segment.type = str(sgmt.type).split(".")[-1]
      segment.file_offset = sgmt.file_offset
      segment.virtual_address = sgmt.virtual_address
      segment.virtual_size = sgmt.virtual_size
      segment.physical_size = sgmt.physical_size
      segments.append(segment)
  return segments


def GetSymbols(symbols):
  """Retrieves the symbols of a ELF binary.
  Args:
    symbols (lief.ELF.Binary.it_filter_symbols): symbols.
  Returns:
    Symbols: the extracted symbols.
  """
  symbls = []
  if len(symbols) > 0:
    for symbl in symbols:
      symbol = Symbol()
      symbol.name = symbl.name
      symbol.type = str(symbl.type).split(".")[-1]
      symbol.version = str(symbl.symbol_version) if symbl.has_version else ""
      symbol.value = symbl.value
      symbol.visibility = str(symbl.visibility).split(".")[-1]
      symbol.binding = str(symbl.binding).split(".")[-1]
      symbls.append(symbol)
  return symbls

def GetLibraries(binary):
  """Retrieves the shared libraries of a ELF binary.
  Args:
    binary (lief.ELF.Binary): binary to extract the libraries from.
  Returns:
    Libraries: the extracted segments.
  """
  libaries = []
  # Get the list of shared libraries
  shared_libs = binary.libraries
  for shared_lib in shared_libs:
    library = Library()
    library.name = shared_lib
    libaries.append(library)
  return libaries

def ParseHeader(header):
  """Parses a ELF binary.
  Args:
    header (lief.ELF.Binary.Header): header to be parsed.
  Returns:
    ParsedHeader: the parsed header details.
  """
  parsed_header = ParsedHeader()
  eflags_str = ""
  if header.machine_type == lief.ELF.ARCH.ARM:
    eflags_str = " - ".join([str(s).split(".")[-1] for s in header.arm_flags_list])
  if header.machine_type in [lief.ELF.ARCH.MIPS,
                             lief.ELF.ARCH.MIPS_RS3_LE,
                             lief.ELF.ARCH.MIPS_X]:
    eflags_str = " - ".join([str(s).split(".")[-1] for s in header.mips_flags_list])

  if header.machine_type == lief.ELF.ARCH.PPC64:
    eflags_str = " - ".join([str(s).split(".")[-1] for s in header.ppc64_flags_list])

  if header.machine_type == lief.ELF.ARCH.HEXAGON:
    eflags_str = " - ".join([str(s).split(".")[-1] for s in header.hexagon_flags_list])

  if header.machine_type == lief.ELF.ARCH.LOONGARCH:
      eflags_str = " - ".join([str(s).split(".")[-1] for s in header.loongarch_flags_list])

  parsed_header.entrypoint = header.entrypoint
  parsed_header.file_type = str(header.file_type).split(".")[-1]
  parsed_header.header_size = header.header_size
  parsed_header.identity_abi_version = header.identity_abi_version
  parsed_header.identity_class = str(header.identity_class).split(".")[-1]
  parsed_header.identity_data = str(header.identity_data).split(".")[-1]
  parsed_header.identity_os_abi = str(header.identity_os_abi).split(".")[-1]
  parsed_header.identity_version = str(header.identity_version).split(".")[-1]
  parsed_header.numberof_sections = header.numberof_sections
  parsed_header.numberof_segments = header.numberof_segments
  parsed_header.machine_type = str(header.machine_type).split(".")[-1]
  parsed_header.object_file_version = str(header.object_file_version).split(".")[-1]
  parsed_header.processor_flags = str(header.processor_flag) + eflags_str
  parsed_header.program_header_offset = header.program_header_offset
  parsed_header.program_header_size = header.program_header_size
  parsed_header.section_header_offset = header.section_header_offset
  parsed_header.section_header_size = header.section_header_size
  return parsed_header


def CurrentTimeMillis():
  return round(time.time() * 1000)


def parse_file(input_file, workflow_id) -> Report:
    """Parse a ELF file.
    - Parse ELF files
    Args:
      input_file (file): ELF file.
      workflow_id (str): The workflow ID
    Returns:
      report (Report): The analysis report.
    """
    start_time = CurrentTimeMillis()
    parsed_binaries = 0
    output = ""
    # Create a report with two sections.
    report = Report("ELF Parser Report")
    details_section = report.add_section()
    summary_section = report.add_section()
    report.summary = "No ELF content found"

    try:
      elf_path = input_file.get("path")
      elf_binary = lief.ELF.parse(elf_path)
      elf_fd = open(elf_path, 'rb')
      if isinstance(elf_binary, lief.ELF.Binary):
        parsed_binaries += 1
        hashes = GetHashes(elf_fd, elf_binary)
        header = ParseHeader(elf_binary.header)
        segments = GetSegments(elf_binary)
        imp_symbols = GetSymbols(elf_binary.imported_symbols)
        exp_symbols = GetSymbols(elf_binary.exported_symbols)
        dyn_symbols = GetSymbols(elf_binary.dynamic_symbols)
        tab_symbols = GetSymbols(elf_binary.symtab_symbols)
        libaries = GetLibraries(elf_binary)
        parsed_elf = ParsedElf(
          hashes, header, segments, imp_symbols, exp_symbols, dyn_symbols,
          tab_symbols, libaries)
        parsed_elf.virtual_size = elf_binary.virtual_size
        parsed_elf.workflow_id = workflow_id
        parsed_elf.processing_time = CurrentTimeMillis() - start_time
        # Plain vanilla json.dumps() doesn't support custom classes.
        # https://stackoverflow.com/questions/3768895/how-to-make-a-class-json-serializable
        output = f'{json.dumps(parsed_elf.__dict__, default=lambda o: o.__dict__, indent=2)}\n'
        report.summary = f'Parsed {parsed_binaries} lief.ELF.Binary'
      elf_fd.close()
    except IOError as e:
      report.summary = f'Error opening ELF file: {str(e)}'
    
    report.priority = Priority.LOW
    summary_section.add_paragraph(report.summary)
    return report, output