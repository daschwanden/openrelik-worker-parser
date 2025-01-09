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

from typing import Callable

from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.task_utils import create_task_result, get_input_files
from openrelik_worker_common.reporting import serialize_file_report


from .app import celery


def task_factory(
    task_name: str,
    task_name_short: str,
    task_metadata: dict,
    parser_function: Callable,
    task_report_function: Callable = None,
):
    """
    Factory function to create parser Celery tasks.

    Args:
        task_name: Full task name for registration.
        task_name_short: Short task name for display.
        task_metadata: Metadata for registration in the core system.
        parser_function: The function to use for analyzing the config file.

    Returns:
        A Celery task function.
    """

    @celery.task(bind=True, name=task_name, metadata=task_metadata)
    def file_parser(
        self,
        pipe_result: str = None,
        input_files: list = None,
        output_path: str = None,
        workflow_id: str = None,
        task_config: dict = None,
    ) -> str:
        """Run the parser on input files."""

        input_files = get_input_files(
            pipe_result, input_files
        )
        output_files = []
        file_reports = []
        task_report = None

        for input_file in input_files:
            report_file = create_output_file(
                output_path,
                display_name=f"{input_file.get('display_name')}-{task_name_short}-report.md",
                data_type=f"worker:openrelik:parser:{task_name_short}:report",
            )
            output_file = create_output_file(
                output_path,
                display_name=f"{input_file.get('display_name')}-{task_name_short}-output.json",
            )

            # Use the provided analysis function.
            parser_report, parser_output = parser_function(input_file, workflow_id)
            file_report = serialize_file_report(
                input_file, report_file, parser_report
            )
            with open(report_file.path, "w", encoding="utf-8") as fh:
                fh.write(parser_report.to_markdown())
            file_reports.append(file_report)
            output_files.append(report_file.to_dict())

            with open(output_file.path, "w", encoding="utf-8") as fh:
                fh.write(parser_output)
            output_files.append(output_file.to_dict())

        if task_report_function:
            task_report = task_report_function(file_reports)

        if not output_files:
            raise RuntimeError(f"{task_name_short} didn't create any output files")

        return create_task_result(
            output_files=output_files,
            workflow_id=workflow_id,
            file_reports=file_reports,
            task_report=task_report,
        )

    return file_parser