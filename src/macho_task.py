# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tomcat configuration analyzer task."""

from .parsers.macho_parser import parse_file
from .factory import task_factory

# Task name used to register and route the task to the correct queue.
TASK_NAME = "openrelik-worker-parser.tasks.macho_file_parser"
TASK_NAME_SHORT = "macho_file_parse"

# Task metadata for registration in the core system.
TASK_METADATA = {
    "display_name": "Parser: Mach-O",
    "description": "Parses Mach-O files",
}

task_factory(
    task_name=TASK_NAME,
    task_name_short=TASK_NAME_SHORT,
    task_metadata=TASK_METADATA,
    parser_function=parse_file,
    task_report_function=None,
)