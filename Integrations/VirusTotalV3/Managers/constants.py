from enum import Enum


PROVIDER_NAME = "VirusTotal"
INTEGRATION_NAME = "VirusTotalV3"

# ACTION NAMES
PING_SCRIPT_NAME = f"{INTEGRATION_NAME} - Ping"
ENRICH_IP_SCRIPT_NAME = f"{INTEGRATION_NAME} - Enrich IP"
ENRICH_HASH_SCRIPT_NAME = f"{INTEGRATION_NAME} - Enrich Hash"
GET_RELATED_URLS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Related URLs"
GET_RELATED_DOMAINS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Related Domains"
GET_RELATED_IPS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Related URLs"
GET_RELATED_HASHES_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Related Hashes"
ENRICH_URL_SCRIPT_NAME = f"{INTEGRATION_NAME} - Enrich URL"
GET_DOMAIN_DETAILS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Domain Details"
SEARCH_GRAPHS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Search Graphs"
SEARCH_ENTITY_GRAPHS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Search Entity Graphs"
GET_GRAPH_DETAILS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Graph Details"
SUBMIT_FILE_SCRIPT_NAME = f"{INTEGRATION_NAME} - Submit File"
DOWNLOAD_FILE_SCRIPT_NAME = f"{INTEGRATION_NAME} - Download File"
ENRICH_IOC_SCRIPT_NAME = f"{INTEGRATION_NAME} - Enrich IOC"
ADD_VOTE_TO_ENTITY_SCRIPT_NAME = "Add Vote To Entity"
ADD_COMMENT_TO_ENTITY_SCRIPT_NAME = "Add Comment To Entity"
SEARCH_IOCS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Search IOCs"

CASE_WALL_LINK = "https://www.virustotal.com/gui/{entity_type}/{entity}/detection"
CASE_WALL_PRIVATE_LINK = (
    "https://www.virustotal.com/gui/private-scanning/analysis/{analysis_id}"
)
EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
DOMAIN_REGEX = r"[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})+"

# DEFAULTS
DEFAULT_COMMENTS_COUNT = 50
PER_PAGE_ITEMS_COUNT = 40
DEFAULT_RELATED_ITEMS_COUNT = 100
MAX_COUNT_OF_GRAPHS = 10
DEFAULT_RELATED_URLS_LIMIT = 40
DEFAULT_RELATED_IPS_LIMIT = 40
DEFAULT_RELATED_HASHES_LIMIT = 40
DEFAULT_RELATED_DOMAINS_LIMIT = 40
DEFAULT_LIMIT = 10
DEFAULT_SANDBOX = "VirusTotal Jujubox"
XTOOL_VALUE = "Google SecOps SOAR"

# analyses statuses
COMPLETED = "completed"
QUEUED = "queued"
IN_PROGRESS = "in-progress"

# ADDITIONAL ENTITY TYPES
EMAIL_TYPE = 101
DOMAIN_TYPE = 102

DATA_ENRICHMENT_PREFIX = "VT3"
COMMENTS_TABLE_TITLE = "Comments: {}"
REPORT_LINK_TITLE = "Report Link: "
SIGMA_ANALYSIS_TITLE = "Sigma Analysis: {}"
GRAPHS_TABLE_TITLE = "Graph {} Links"
INSIGHT_TITLE = "Report: {}"

MD5_LENGTH = 32
SHA1_LENGTH = 40
SHA256_LENGTH = 64

IGNORED_CATEGORIES = ["confirmed-timeout", "type-unsupported", "timeout", "failure"]

RELATED_RESULTS_TYPE = {"combined": "Combined", "per_entity": "Per Entity"}

IOC_TYPES = {
    "filehash": "Filehash",
    "url": "URL",
    "domain": "Domain",
    "ip_address": "IP Address",
}
IOC_LINK_ITEMS_MAPPING = {
    IOC_TYPES.get("filehash"): "file",
    IOC_TYPES.get("url"): "url",
    IOC_TYPES.get("domain"): "domain",
    IOC_TYPES.get("ip_address"): "ip-address",
}

IOC_LINK_STRUCTURE = "https://www.virustotal.com/gui/{ioc_type}/{ioc}/detection"
DEFAULT_RESUBMIT_DAYS = 30
DEFAULT_MAX_IOC_LIMIT = 10
DEFAULT_SORT_ORDER = "Descending"

# Connector
CONNECTOR_NAME = f"{INTEGRATION_NAME} - Livehunt Notifications Connector"
DEFAULT_TIME_FRAME = 1
DEFAULT_NOTIFICATIONS_LIMIT = 40
DEVICE_VENDOR = "VirusTotal"
DEVICE_PRODUCT = "VirusTotal"
TIMESTAMP_KEY = "notification_date"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
FALLBACK_NAME = "VT Livehunt Notification"


class Verdict(str, Enum):
    MALICIOUS: str = "VERDICT_MALICIOUS"
    CLEAN: str = "VERDICT_UNDETECTED"


WIDGET_LIGHT_THEME_COLORS = {
    "theme": "light",
    "fg1": "4f5064",
    "bg1": "ffffff",
    "bg2": "f4f5fa",
    "bd1": "d2d7e9",
}

WIDGET_DARK_THEME_COLORS = {
    "theme": "dark",
    "fg1": "b2b2b8",
    "bg1": "1b1b22",
    "bg2": "1f1f29",
    "bd1": "303045",
}

WIDGET_CHRONICLE_THEME_COLORS = {
    "theme": "dark",
    "fg1": "ffffff",
    "bg1": "212c44",
    "bg2": "3a4a6c",
    "bd1": "5d708a",
}

WIDGET_THEME_MAPPING = {
    "Light": WIDGET_LIGHT_THEME_COLORS,
    "Dark": WIDGET_DARK_THEME_COLORS,
    "Chronicle": WIDGET_CHRONICLE_THEME_COLORS,
}

ERROR_RESPONSE_TEXTS = {
    "api_key_error": "Wrong API key",
    "permission_error": "not authorized to perform the requested operation",
}

PERMISSION_EXCEPTION_TEXT = (
    "Your API key doesn't support this feature. Please upgrade it."
)

MITRE_SEVERITY = ["HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]

SEVERITY_DIC = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "UNKNOWN": 0}
IOC_SEVERITY_MAPPING = {
    "SEVERITY_NONE": False,
    "SEVERITY_UNKNOWN": False,
    "SEVERITY_INFO": False,
    "SEVERITY_LOW": False,
    "SEVERITY_MEDIUM": True,
    "SEVERITY_HIGH": True,
    "SEVERITY_CRITICAL": True,
}

ORDER_BY_MAPPING = {
    "Use Default Order": None,
    "Last Submission Date": "last_submission_date",
    "First Submission Date": "first_submission_date",
    "Positives": "positives",
    "Times Submitted": "times_submitted",
    "Creation Date": "creation_date",
    "Last Modification Date": "last_modification_date",
    "Last Update Date": "last_update_date",
}

SORT_ORDER_MAPPING = {"Descending": "-", "Ascending": "+"}
