import json
import sys
from FileManager import FileManager
from ScriptResult import (
    EXECUTION_STATE_COMPLETED,
    EXECUTION_STATE_FAILED,
    EXECUTION_STATE_INPROGRESS,
)
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon.extraction import extract_configuration_param, extract_action_param
from TIPCommon.transformation import construct_csv
from VirusTotalManager import VirusTotalManager
from constants import (
    PROVIDER_NAME,
    INTEGRATION_NAME,
    SUBMIT_FILE_SCRIPT_NAME,
    DEFAULT_COMMENTS_COUNT,
    COMPLETED,
    COMMENTS_TABLE_TITLE,
    REPORT_LINK_TITLE,
    INSIGHT_TITLE,
    PERMISSION_EXCEPTION_TEXT,
    CASE_WALL_PRIVATE_LINK,
)
from UtilsManager import is_private_file_malicious
from VirusTotalParser import Hash
from exceptions import (
    ForceRaiseException,
    VirusTotalInvalidApiKeyException,
    VirusTotalNotFoundException,
)


def start_operation(siemplify, manager, private_subm, fetch_mitre_details):
    files_str = extract_action_param(
        siemplify, param_name="File Paths", is_mandatory=True, print_value=True
    )
    address = extract_action_param(
        siemplify,
        param_name="Linux Server Address",
        is_mandatory=False,
        print_value=True,
    )
    username = extract_action_param(
        siemplify, param_name="Linux Username", is_mandatory=False, print_value=True
    )
    password = extract_action_param(
        siemplify, param_name="Linux Password", is_mandatory=False, print_value=True
    )
    files = [file.strip() for file in files_str.split(",") if file] if files_str else []

    result_value = {"in_progress": {}, "failed": {}, "done": {}, "analysis_ids": {}}
    if fetch_mitre_details:
        result_value = {
            "in_progress": {},
            "failed": {},
            "done": {},
            "analysis_ids": {},
            "mitre_progress": {},
            "mitre_failed": {},
            "mitre_done": {},
        }
    output_message = ""
    status = EXECUTION_STATE_INPROGRESS
    file_bytes = None
    file_manager = (
        FileManager(address, username, password)
        if address and username and password
        else None
    )

    failed_files, successful_files = [], []
    for file in files:
        try:
            submit_url = manager.get_upload_url(is_private=private_subm)

            if file_manager:
                file_bytes = file_manager.get_remote_unix_file_content(file)

            analysis_id = manager.get_analysis(
                url=submit_url, file=file, file_bytes=file_bytes
            )
            # Fill json with every entity data
            result_value["in_progress"][file] = analysis_id
            successful_files.append(file)
        except (VirusTotalInvalidApiKeyException, ForceRaiseException) as err:
            output_message = f"Error executing action 'Submit File'. Reason: {err} \n"
            raise
        except Exception as err:
            output_message = f"Error executing action 'Submit File'. Reason: {err} \n"
            failed_files.append(file)
            result_value["failed"][file] = file
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(err)
            if PERMISSION_EXCEPTION_TEXT in output_message:
                status = EXECUTION_STATE_FAILED
                raise Exception(PERMISSION_EXCEPTION_TEXT)

    if successful_files:
        output_message += (
            f"Waiting for results for the following files: \n {PROVIDER_NAME} \n"
        )
        result_value = json.dumps(result_value)

    if failed_files:
        output_message += (
            f"Action wasn’t able to return details about the following "
            f"domains using {PROVIDER_NAME}: "
            f"\n {', '.join(failed_files)} \n"
        )

    if not successful_files:
        output_message = "No details about the files were retrieved."
        result_value = False
        status = EXECUTION_STATE_COMPLETED

    return output_message, result_value, status


def query_operation_status(
    siemplify,
    manager,
    task_analysis,
    threshold,
    percentage_threshold,
    private_subm,
    fetch_mitre_details,
    lowest_mitre_severity,
    retrieve_ai_summary,
):
    """Query status for submitted files and prepare output message based on results."""
    completed_files = {}
    not_completed_files = {}
    completed_hashes_analysis_ids = task_analysis.get("analysis_ids", {})
    if fetch_mitre_details:
        mitre_completed_files = {}
    mitre_files = {}

    for file, analysis_id in task_analysis["in_progress"].items():
        try:
            analysis_status, file_hash = manager.check_analysis_status(
                analysis_id=analysis_id, get_data=True, is_private=private_subm
            )
            # Fill not completed and completed dicts with relevant items
            if analysis_status != COMPLETED:
                not_completed_files[file] = analysis_id
            else:
                completed_files[file] = file_hash
                completed_hashes_analysis_ids[file_hash] = analysis_id
                if fetch_mitre_details:
                    mitre_response = manager.get_mitre(
                        file_hash=file_hash,
                        show_entity_status=True,
                        lowest_mitre_severity=lowest_mitre_severity,
                    )
                    task_analysis["mitre_progress"][file] = file_hash

        except Exception as e:
            siemplify.LOGGER.error(
                f"An error occurred when checking status for file {file}"
            )
            siemplify.LOGGER.exception(e)

    if fetch_mitre_details:
        for file, file_hash in task_analysis["mitre_progress"].items():
            try:
                mitre_response = manager.get_mitre(
                    file_hash=file_hash,
                    is_private=private_subm,
                    show_entity_status=True,
                    lowest_mitre_severity=lowest_mitre_severity,
                )
                if mitre_response.status == COMPLETED:
                    mitre_completed_files[file] = file_hash

            except Exception as e:
                siemplify.LOGGER.error(
                    f"An error occurred when checking status for file {file}"
                )
                siemplify.LOGGER.exception(e)

    # Remove completed filenames from in progress files
    for key in completed_files.keys():
        task_analysis["in_progress"].pop(key)
    # Update completed files with completed_files dict
    task_analysis["done"].update(completed_files)
    # Update analysis_ids
    task_analysis["analysis_ids"].update(completed_hashes_analysis_ids)

    if fetch_mitre_details:
        for key in mitre_completed_files:
            task_analysis["mitre_progress"].pop(key)
        # Update completed files with completed_files dict
        task_analysis["mitre_done"].update(mitre_completed_files)
        mitre_files = task_analysis["mitre_done"]

    if task_analysis["in_progress"]:
        output_message = (
            f"Waiting for results for the following files: "
            f"\n {', '.join(task_analysis['in_progress'].keys())} \n"
        )
        result_value = json.dumps(task_analysis)
        status = EXECUTION_STATE_INPROGRESS
    elif fetch_mitre_details and task_analysis["mitre_progress"]:
        output_message = (
            f"Waiting for results for the following files: "
            f"\n {', '.join(task_analysis['mitre_progress'].keys())} \n"
        )
        result_value = json.dumps(task_analysis)
        status = EXECUTION_STATE_INPROGRESS
    else:
        output_message, result_value, status = finish_operation(
            siemplify=siemplify,
            manager=manager,
            completed_files=task_analysis["done"],
            mitre_completed_files=mitre_files,
            failed_files=task_analysis["failed"],
            threshold=threshold,
            percentage_threshold=percentage_threshold,
            private_subm=private_subm,
            fetch_mitre_details=fetch_mitre_details,
            lowest_mitre_severity=lowest_mitre_severity,
            analysis_ids=task_analysis["analysis_ids"],
            retrieve_ai_summary=retrieve_ai_summary,
        )

    return output_message, result_value, status


def is_submission_risky(
    hash_data: Hash,
    private_submission: bool,
    engine_count_threshold: int,
    engine_percentage_threshold: int,
) -> bool:
    """
    Determine if a submission is risky based on:
    - Whether it's a private malicious file,
    - AV engine hit counts,
    - AV engine hit percentage.

    Args:
        hash_data (Hash): Data associated with the submission.
        private_submission (bool):Whether the file was submitted privately.
        engine_count_threshold (int): Minimum number of AV engines
        that must flag the file. If <= 0, this check is skipped.
        engine_percentage_threshold (int): Minimum percentage of
        AV engines that must flag the file.
    """
    if private_submission:
        return is_private_file_malicious(
            hash_data=hash_data, private_submission=private_submission
        )

    if (
        engine_count_threshold
        and isinstance(engine_count_threshold, int)
        and engine_count_threshold > 0
    ):
        return hash_data.threshold >= engine_count_threshold

    return int(hash_data.percentage_threshold) >= engine_percentage_threshold


def finish_operation(
    siemplify,
    manager,
    completed_files,
    mitre_completed_files,
    failed_files,
    threshold,
    percentage_threshold,
    private_subm,
    fetch_mitre_details,
    lowest_mitre_severity,
    analysis_ids,
    retrieve_ai_summary,
):
    """Finsh operation and build json results, data table and output message."""
    whitelist_str = extract_action_param(
        siemplify, param_name="Engine Whitelist", is_mandatory=False, print_value=True
    )
    retrieve_comments = extract_action_param(
        siemplify, param_name="Retrieve Comments", is_mandatory=False, input_type=bool
    )
    max_returned_comments = extract_action_param(
        siemplify,
        param_name="Max Comments To Return",
        is_mandatory=False,
        input_type=int,
        default_value=DEFAULT_COMMENTS_COUNT,
    )
    whitelists = (
        [item.strip() for item in whitelist_str.split(",") if item]
        if whitelist_str
        else []
    )

    output_massage = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    successful_files = []
    failed_files = list(failed_files.keys())
    not_found_engines = set()
    json_results = {}
    comments = []
    is_risky = False

    for file, entity in completed_files.items():
        siemplify.LOGGER.info(f"Started processing file: {file}")

        try:
            hash_data = manager.get_hash_data(
                file_hash=entity, report_link_suffix="file", is_private=private_subm
            )
            hash_data.set_supported_engines(whitelists)
            not_found_engines.update(set(hash_data.invalid_engines))

            if retrieve_comments:
                comments = []
                if not private_subm:
                    try:
                        comments: list[str] = manager.get_comments(
                            url_type="files",
                            entity=entity,
                            limit=max_returned_comments,
                        )

                    except VirusTotalNotFoundException:
                        siemplify.LOGGER.info(
                            f"No public comments found for file: {file}"
                        )

            try:
                # Retrieve AI Generated Summary
                if private_subm and retrieve_ai_summary:
                    hash_data.generated_ai_summary = manager.get_ai_summary(
                        file_hash=entity
                    )
                    hash_data.ai_summary_available = True

            except Exception as err:
                siemplify.LOGGER.error(
                    f"An error occurred on generating AI Summary for {file}"
                )
                hash_data.generated_ai_summary = ""
                siemplify.LOGGER.exception(err)

            related_mitre_tactics = []
            related_mitre_techniques = []
            if fetch_mitre_details and file in mitre_completed_files.keys():
                mitre_response = manager.get_mitre(
                    file_hash=mitre_completed_files[file],
                    is_private=private_subm,
                    show_entity_status=True,
                    lowest_mitre_severity=lowest_mitre_severity,
                )
                related_mitre_tactics = mitre_response.mitre_tactics
                related_mitre_techniques = mitre_response.mitre_techniques

            if not private_subm:
                # Add case wall table for entity
                siemplify.result.add_data_table(
                    title=f"Results: {file}",
                    data_table=construct_csv(hash_data.to_table()),
                )
            # Fill json with every entity data
            json_results[file] = hash_data.to_json(comments=comments)
            is_risky_value = is_submission_risky(
                hash_data=hash_data,
                private_submission=private_subm,
                engine_count_threshold=threshold,
                engine_percentage_threshold=percentage_threshold,
            )
            if is_risky_value:
                is_risky = True
            json_results[file].update({"is_risky": is_risky_value})
            if related_mitre_tactics:
                json_results[file].update(
                    {"related_mitre_tactics": related_mitre_tactics}
                )
            if related_mitre_techniques:
                json_results[file].update(
                    {"related_mitre_techniques": related_mitre_techniques}
                )

            # Create case wall table for comments
            if comments:
                siemplify.result.add_data_table(
                    title=COMMENTS_TABLE_TITLE.format(file),
                    data_table=construct_csv(
                        [comment.to_table() for comment in comments]
                    ),
                )

            if not private_subm:
                if hash_data.report_link:
                    siemplify.result.add_entity_link(
                        REPORT_LINK_TITLE, hash_data.report_link
                    )

            private_report_link = CASE_WALL_PRIVATE_LINK.format(
                analysis_id=analysis_ids.get(entity)
            )
            siemplify.create_case_insight(
                INTEGRATION_NAME,
                INSIGHT_TITLE.format(file),
                hash_data.to_insight(
                    threshold=threshold or f"{percentage_threshold}%",
                    private_report_link=private_report_link if private_subm else None,
                ),
                entity,
                0,
                0,
            )

            successful_files.append(file)
            siemplify.LOGGER.info(f"Finished processing file: {file}")

        except Exception as e:
            if isinstance(e, (ForceRaiseException, VirusTotalInvalidApiKeyException)):
                raise
            failed_files.append(file)
            siemplify.LOGGER.error(f"An error occurred on file: {file}")
            siemplify.LOGGER.exception(e)

    if successful_files:
        output_massage += (
            f"Successfully returned details about the following "
            f"files using {PROVIDER_NAME}: "
            f"\n {', '.join(successful_files)} \n"
        )

    if failed_files:
        output_massage += (
            f"Action wasn’t able to return details about the "
            f"following domains using {PROVIDER_NAME}: "
            f"\n {', '.join(failed_files)} \n"
        )

    if not_found_engines:
        output_massage += (
            f"The following whitelisted engines were not found in "
            f"{PROVIDER_NAME}: \n{', '.join(not_found_engines)} \n"
        )

    if not successful_files:
        output_massage = "No details about the files were retrieved."
        result_value = False

    if json_results:
        siemplify.result.add_result_json(
            {
                "results": convert_dict_to_json_result_dict(json_results),
                "is_risky": is_risky,
            }
        )

    return output_massage, result_value, status


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SUBMIT_FILE_SCRIPT_NAME

    api_key = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="API Key"
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Verify SSL",
        default_value=True,
        input_type=bool,
    )

    threshold = extract_action_param(
        siemplify,
        param_name="Engine Threshold",
        is_mandatory=False,
        input_type=int,
        print_value=True,
    )
    percentage_threshold = extract_action_param(
        siemplify,
        param_name="Engine Percentage Threshold",
        is_mandatory=False,
        input_type=int,
        print_value=True,
    )
    private_subm = extract_action_param(
        siemplify,
        param_name="Private Submission",
        is_mandatory=False,
        input_type=bool,
        print_value=True,
    )
    fetch_mitre_details = extract_action_param(
        siemplify,
        param_name="Fetch MITRE Details",
        input_type=bool,
        default_value=False,
        print_value=True,
    )
    lowest_mitre_severity = extract_action_param(
        siemplify, param_name="Lowest MITRE Technique Severity", print_value=True
    )
    retrieve_ai_summary = extract_action_param(
        siemplify,
        param_name="Retrieve AI Summary",
        input_type=bool,
        default_value=False,
        print_value=True,
    )

    lowest_mitre_severity = lowest_mitre_severity.upper()

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    result_value = False
    status = EXECUTION_STATE_INPROGRESS

    try:
        if not threshold and not percentage_threshold:
            raise Exception(
                'either "Engine Threshold" or "Engine Percentage Threshold" '
                "should be provided."
            )

        if percentage_threshold and not 0 <= percentage_threshold <= 100:
            raise Exception(
                'value for the parameter "Engine Percentage Threshold" '
                "is invalid. Please check it. The value should be "
                "in range from 0 to 100"
            )

        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        if is_first_run:
            output_message, result_value, status = start_operation(
                siemplify=siemplify,
                manager=manager,
                private_subm=private_subm,
                fetch_mitre_details=fetch_mitre_details,
            )

        if status == EXECUTION_STATE_INPROGRESS:
            task_analysis_json = (
                result_value
                if result_value
                else extract_action_param(
                    siemplify, param_name="additional_data", default_value=result_value
                )
            )
            output_message, result_value, status = query_operation_status(
                siemplify=siemplify,
                manager=manager,
                task_analysis=json.loads(task_analysis_json),
                threshold=threshold,
                percentage_threshold=percentage_threshold,
                private_subm=private_subm,
                fetch_mitre_details=fetch_mitre_details,
                lowest_mitre_severity=lowest_mitre_severity,
                retrieve_ai_summary=retrieve_ai_summary,
            )

    except Exception as err:
        output_message = f"Error executing action “Submit File”. Reason: {err}"
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        f"\n  status: {status}"
        f"\n  is_success: {result_value}"
        f"\n  output_message: {output_message}"
    )
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == "True"
    main(is_first_run)
