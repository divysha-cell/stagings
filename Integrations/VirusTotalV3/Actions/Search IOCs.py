from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon.extraction import extract_action_param, extract_configuration_param

from constants import (
    DEFAULT_MAX_IOC_LIMIT,
    DEFAULT_SORT_ORDER,
    INTEGRATION_NAME,
    IOC_SEVERITY_MAPPING,
    ORDER_BY_MAPPING,
    PROVIDER_NAME,
    SEARCH_IOCS_SCRIPT_NAME,
    SORT_ORDER_MAPPING,
)
from exceptions import VirusTotalInvalidLimitError
from UtilsManager import check_if_entity_exists
from VirusTotalManager import VirusTotalManager


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SEARCH_IOCS_SCRIPT_NAME

    siemplify.LOGGER.info("---------------- Main - Param Init ----------------")

    api_key = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="API Key",
        remove_whitespaces=False,
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Verify SSL",
        default_value=True,
        input_type=bool,
    )

    # Parameters
    query = extract_action_param(
        siemplify, param_name="Query", is_mandatory=True, print_value=False
    )
    create_entities = extract_action_param(
        siemplify,
        param_name="Create Entities",
        input_type=bool,
        is_mandatory=True,
        print_value=True,
    )
    order_by = extract_action_param(
        siemplify,
        param_name="Order By",
        is_mandatory=True,
        default_value=ORDER_BY_MAPPING.get("Use Default Order"),
        print_value=True,
    )
    sort_order = extract_action_param(
        siemplify,
        param_name="Sort Order",
        is_mandatory=False,
        default_value=DEFAULT_SORT_ORDER,
        print_value=True,
    )
    max_ioc_to_return = extract_action_param(
        siemplify,
        param_name="Max IOCs To Return",
        default_value=DEFAULT_MAX_IOC_LIMIT,
        input_type=int,
        print_value=True,
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    existing_entities_message = (
        "The following IOCs were not created as new entities, "
        "as they already exists in the system: "
    )
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    error_messages = []
    is_internal = False
    is_enriched = False
    properties = {}
    success_entities = []
    existing_entities = []

    try:
        if max_ioc_to_return < 1:
            raise VirusTotalInvalidLimitError(
                'Invalid value was provided for "Max IOCs To Return": '
                f"{max_ioc_to_return}. Positive number should be provided."
            )

        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        search_data = manager.search_iocs(
            query=query,
            limit=max_ioc_to_return,
            order_by=ORDER_BY_MAPPING.get(order_by),
            sort_order=None if order_by is None else SORT_ORDER_MAPPING.get(sort_order),
        )

        if search_data:
            output_message = (
                "Successfully returned IOCs based on the provided query from "
                f"{PROVIDER_NAME}."
            )
            search_data_json = {"data": [ioc.to_json() for ioc in search_data]}
            for ioc in search_data_json.get("data"):
                if create_entities:
                    if ioc["type"] == "domain":
                        entity_type = EntityTypes.DOMAIN
                        entity_identifier = ioc["id"]
                    elif ioc["type"] == "url":
                        entity_type = EntityTypes.URL
                        entity_identifier = ioc["attributes"]["url"]
                    elif ioc["type"] == "file":
                        entity_type = EntityTypes.FILEHASH
                        entity_identifier = ioc["id"]
                    else:
                        raise ValueError(f'Unsupported Entity type: \'{ioc["type"]}\'')

                    threat_severity = ioc.get("attributes", {}).get(
                        "threat_severity", {}
                    )

                    is_suspicious = IOC_SEVERITY_MAPPING.get(
                        threat_severity.get("threat_severity_level"), False
                    )
                    is_vulnerable = threat_severity.get("threat_severity_data", {}).get(
                        "has_vulnerabilities", False
                    )

                    try:
                        if check_if_entity_exists(
                            logger=siemplify.LOGGER,
                            target_entities=siemplify.target_entities,
                            entity_identifier=entity_identifier,
                            entity_type=entity_type,
                        ):
                            message = (
                                f"Entity with identifier {entity_identifier} "
                                "hasn't been added to the case, as it already "
                                "exists."
                            )
                            existing_entities.append(entity_identifier)
                            siemplify.LOGGER.info(message)
                        else:
                            siemplify.add_entity_to_case(
                                entity_identifier=entity_identifier,
                                entity_type=entity_type,
                                is_internal=is_internal,
                                is_suspicous=is_suspicious,
                                is_enriched=is_enriched,
                                is_vulnerable=is_vulnerable,
                                properties=properties,
                            )
                            siemplify.LOGGER.info(
                                f"Entity with identifier {entity_identifier} "
                                f"{entity_type} has been added to the case."
                            )
                            success_entities.append(entity_identifier)
                    except Exception:
                        error_message = f"Entity {entity_identifier} Creation failed."
                        siemplify.LOGGER.error(error_message)
                        error_messages.append(error_message)

            siemplify.result.add_result_json(search_data_json)
            if existing_entities:
                output_message += (
                    f"\n{existing_entities_message}" f'{", ".join(existing_entities)}'
                )
        else:
            output_message = "No IOCs were found for the provided query."
            result_value = False

    except Exception as err:
        output_message = f"Error executing action “Search IOCs”. Reason: {err}"
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
    main()
