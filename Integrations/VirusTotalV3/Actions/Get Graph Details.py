from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon.extraction import extract_configuration_param, extract_action_param
from TIPCommon.transformation import construct_csv
from VirusTotalManager import VirusTotalManager
from constants import (
    PROVIDER_NAME,
    INTEGRATION_NAME,
    GET_GRAPH_DETAILS_SCRIPT_NAME,
    DEFAULT_COMMENTS_COUNT,
    GRAPHS_TABLE_TITLE,
)
from exceptions import ForceRaiseException, VirusTotalInvalidApiKeyException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_GRAPH_DETAILS_SCRIPT_NAME

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
    # Parameters
    graphs = extract_action_param(
        siemplify, param_name="Graph ID", is_mandatory=True, print_value=True
    )
    max_returned_links = extract_action_param(
        siemplify,
        param_name="Max Links To Return",
        is_mandatory=False,
        input_type=int,
        default_value=DEFAULT_COMMENTS_COUNT,
    )
    graph_ids = (
        [graph_id.strip() for graph_id in graphs.split(",") if graph_id.strip()]
        if graphs
        else []
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    successful_graphs = []
    failed_graphs = []
    results = []

    try:
        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        for graph_id in graph_ids:
            try:
                graph_result = manager.get_graph(
                    graph_id=graph_id, limit=max_returned_links
                )

                if graph_result:
                    # Create Case wall table for each graph_id
                    siemplify.result.add_data_table(
                        title=GRAPHS_TABLE_TITLE.format(graph_id),
                        data_table=construct_csv(graph_result.to_table()),
                    )
                    results.append(graph_result)

                    successful_graphs.append(graph_id)

            except (VirusTotalInvalidApiKeyException, ForceRaiseException) as e:
                error_message = f"error occured that requires to stop the execution:{e}"
                siemplify.LOGGER.error(error_message)
                raise
            except Exception as err:
                failed_graphs.append(graph_id)
                siemplify.LOGGER.error(
                    f"Action wasn't able to retrieve data for {graph_id}: Reason: {err}"
                )
                siemplify.LOGGER.exception(err)

        if results:
            siemplify.result.add_result_json([graph.to_json() for graph in results])

        if successful_graphs:
            output_message += (f"Successfully returned details about the following "
                               f"graphs in {PROVIDER_NAME}: \n "
                               f"{', '.join(successful_graphs)} \n")

        if failed_graphs:
            output_message += (f"Action wasn’t able to return details about the "
                               f"following graphs in {PROVIDER_NAME}: "
                               f"\n {', '.join(failed_graphs)} \n")

        if not successful_graphs:
            output_message = "No information about the provided graphs was found."
            result_value = False

    except Exception as err:
        output_message = f"Error executing action “Get Graph Details”. Reason: {err}"
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        f"\n  status: {status}\n  "
        f"is_success: {result_value}\n  output_message: {output_message}"
    )
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
