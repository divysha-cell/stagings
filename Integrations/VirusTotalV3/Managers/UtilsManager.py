from __future__ import annotations

import base64
import re
import urllib.parse
import tldextract
from SiemplifyLogger import SiemplifyLogger
from SiemplifyDataModel import EntityTypes
from constants import (
    EMAIL_REGEX,
    DOMAIN_REGEX,
    EMAIL_TYPE,
    DOMAIN_TYPE,
    IOC_TYPES,
    TIME_FORMAT,
    MITRE_SEVERITY,
    SEVERITY_DIC,
    Verdict
)
from TIPCommon.types import Entity
import os
import datetime

WHITELIST_FILTER = 1
BLACKLIST_FILTER = 2
JAVA_SCRIPT_PATTERN = re.compile(
    r"<\s*script\s*>.*?<\s*/\s*script\s*>",
    re.IGNORECASE | re.DOTALL
)

def get_entity_original_identifier(entity: Entity):
    """
    helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get("OriginalIdentifier", entity.identifier)


def prepare_cached_widget(html_content: str) -> str:
    """
    Stripping the excessive data from html
    Args:
        html_content: the widget content to be stripped

    Returns:
        Modified html content
    """
    tags_to_strip = [
        r"<nav>.*?</nav>",
        r"<section rel=\"iocs\".*?</section>",
        r"<section rel=\"graph\".*?</section>",
        r"<section rel=\"attribution\".*?</section>",
        r"<script.*?</script>",
    ]
    for tag in tags_to_strip:
        html_content = re.sub(tag, "", html_content, flags=re.DOTALL)
    return "".join(html_content.replace("VT Augment by", "Cached Widget").splitlines())


def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def prepare_entity_for_manager(entity):
    if entity.entity_type == EntityTypes.URL:
        return encode_url(get_entity_original_identifier(entity))

    return get_entity_original_identifier(entity)


def get_entity_type(entity):
    """
    Helper function for getting entity type
    :param entity: entity from which function will get type
    :return: {str} entity type
    """
    if (
        re.search(EMAIL_REGEX, get_entity_original_identifier(entity))
        and entity.entity_type == EntityTypes.USER
    ):
        return EMAIL_TYPE
    if (
        re.search(DOMAIN_REGEX, get_entity_original_identifier(entity))
        and entity.entity_type == EntityTypes.URL
    ):
        return DOMAIN_TYPE

    return entity.entity_type


def get_domain_from_entity(identifier):
    """
    Extract domain from entity identifier
    :param identifier: {str} the identifier of the entity
    :return: {str} domain part from entity identifier
    """
    if "@" in identifier:
        return identifier.split("@", 1)[-1]
    try:
        result = tldextract.extract(identifier)
        if result.suffix:
            return ".".join([result.domain, result.suffix])
        return result.domain
    except ImportError:
        raise ImportError("tldextract is not installed. Use pip and install it.")


def save_attachment(path, name, content):
    """
    Save attachment to local path
    :param path: {str} Path of the folder, where files should be saved
    :param name: {str} File name to be saved
    :param content: {str} File content
    :return: {str} Path to the downloaded files
    """

    # Create path if not exists
    if not os.path.exists(path):
        raise Exception(f"Folder {path} not found.")
    # File local path
    local_path = os.path.join(path, name)
    with open(local_path, "wb") as file:
        file.write(content.encode(encoding="UTF-8"))
        file.close()

    return local_path


def convert_days_to_milliseconds(days):
    """
    Convert days to milliseconds
    :param days: {int} days to convert
    :return: {int} converted milliseconds
    """
    return days * 24 * 60 * 60 * 1000


def convert_comma_separated_to_list(comma_separated):
    """
    Convert comma-separated string to list
    :param comma_separated: String with comma-separated values
    :return: List of values
    """
    return (
        [item.strip() for item in comma_separated.split(",")] if comma_separated else []
    )


def convert_list_to_comma_string(values_list):
    """
    Convert list to comma-separated string
    :param values_list: List of values
    :return: String with comma-separated values
    """
    return (
        ", ".join(str(v) for v in values_list)
        if values_list and isinstance(values_list, list)
        else values_list
    )


def prepare_ioc_for_manager(ioc, ioc_type):
    """
    Prepare ioc for manager
    :param ioc: {str} ioc
    :param ioc_type: {str} ioc type
    :return: {str} transformed ioc
    """
    if ioc_type == IOC_TYPES.get("url"):
        return encode_url(ioc)

    return ioc


def datetime_to_rfc3339(datetime_obj: datetime.datetime) -> str:
    """
    Convert datetime object to RFC 3999 representation
    :param datetime_obj: {datetime.datetime} The datetime object to convert
    :return: {str} The RFC 3999 representation of the datetime
    """
    return datetime_obj.strftime(TIME_FORMAT)


def pass_whitelist_filter(
    siemplify, whitelist_as_a_blacklist, model, model_key, whitelist=None
):
    """
    Apply whitelist filtering based on the given parameters.

    Args:
        siemplify (Siemplify): An instance of the Siemplify class.
        whitelist_as_a_blacklist (bool): Flag indicating whether to treat
        the whitelist as a blacklist.
        model (str): The model to filter against.
        model_key (str): The key within the model to use for filtering.
        whitelist (list, optional): List of items to whitelist. Defaults to None.

    Returns:
        bool: True if the model passes the whitelist filter, False otherwise.

    Raises:
        ValueError: If the model or model_key is not provided.

    """
    # whitelist filter
    whitelist = whitelist or siemplify.whitelist
    whitelist_filter_type = (
        BLACKLIST_FILTER if whitelist_as_a_blacklist else WHITELIST_FILTER
    )
    model_value = getattr(model, model_key)
    model_values = model_value if isinstance(model_value, list) else [model_value]

    if whitelist:
        for value in model_values:
            if whitelist_filter_type == BLACKLIST_FILTER and value in whitelist:
                siemplify.LOGGER.info(f"'{value}' did not pass blacklist filter.")
                return False

            if whitelist_filter_type == WHITELIST_FILTER and value not in whitelist:
                siemplify.LOGGER.info(f"'{value}' did not pass whitelist filter.")
                return False

    return True


def get_highest_severity(signature_list) -> str:
    """
    Get the Highest Severity available in mitre technique

    Args:
        technique_severity_list: It takes signature list in mitre technique

    Returns:
        {str} Return Highest severity in signature list in mitre technique
    """
    for p in MITRE_SEVERITY:
        if p in signature_list:
            return p
    return " ".join([str(elem) for elem in MITRE_SEVERITY[-1:]])  # may be Info


def compare_severity(technique_severity, lowest_mitre_technique):
    """
    Check the item severity should be greater than lowest mitre technique

    Args:
        lowest_mitre_technique: It takes severity input as a parameter
        technique_severity: sealing severity value of mitre technique
    Returns:
        {bool} Return true if item severity is higher or equal else return false
    """
    if SEVERITY_DIC[technique_severity] >= SEVERITY_DIC[lowest_mitre_technique]:
        return True
    else:
        return False


def remove_duplicate_mitre(json_data) -> list:
    """
    Remove duplicate items from the json response

    Args:
        It takes Json response and filter out duplicate items
    Returns:
        {list} Returns list of unique mitre technique
    """
    unique_identifier = set()
    unique_data = []

    for data in json_data:
        identifier = (data["id"], data["severity"])
        if identifier not in unique_identifier:
            unique_identifier.add(identifier)
            unique_data.append(data)
    sorted_data = sorted(
        unique_data, key=lambda d: SEVERITY_DIC[d["severity"]] + 1, reverse=True
    )
    return sorted_data


def check_if_entity_exists(
    logger: SiemplifyLogger,
    target_entities: list,
    entity_identifier: str,
    entity_type: str,
) -> bool:
    """Check if a user entity with the specified identifier and
    type exists in the target entities.

    Args:
        logger: The SiemplifyLogger object.
        target_entities: The list of target entities to search for a match.
        entity_identifier: The identifier of the entity to check.
        entity_type: The type of the entity to check.

    Returns:
        bool: True if an entity with the given identifier and type exists in
        the target entities, False otherwise.
    """
    logger.info(
        f"Checking if User entity {entity_identifier} of type "
        f"{entity_type.strip()} exists in target entities."
    )
    for entity in target_entities:
        if (
            entity.identifier.strip() == entity_identifier
            and entity.entity_type == entity_type.strip()
        ):
            logger.info("Found existing matching entity by type and identifier")

            return True

    return False


def is_private_file_malicious(hash_data, private_submission: bool) -> bool:
    """
    Check whether a private file submission is malicious.
    Args:
         hash_data (datamodels.Hash): Data associated with the submission.
         private_submission(bool): Whether the file was submitted privately.

    Returns:
        bool: True if the private file is considered malicious, otherwise false.
    """
    return (
            private_submission
            and hash_data.threat_verdict == Verdict.MALICIOUS
    )


def parse_entity(entity: str) -> str:
    """
    Checks if the given entity contains JavaScript code within <script> tags.

    If JavaScript code is found, the entity is URL-encoded using urllib.parse.quote().
    Otherwise, the original entity is returned unchanged.

    Args:
        entity (str): The string to be parsed.

    Returns:
        str: The URL-encoded string if JavaScript code is found, or the original string
            otherwise.
    """
    if JAVA_SCRIPT_PATTERN.search(entity):
        return urllib.parse.quote(entity)
    return entity
