"""SDK 内部统一使用的错误码和异常定义。"""

from enum import StrEnum


class VerificationErrorCode(StrEnum):
    INVALID_AGENT_ID = "INVALID_AGENT_ID"
    INVALID_METADATA = "INVALID_METADATA"
    METADATA_FETCH_FAILED = "METADATA_FETCH_FAILED"
    METADATA_HOST_MISMATCH = "METADATA_HOST_MISMATCH"
    KEY_NOT_FOUND = "KEY_NOT_FOUND"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_EXPIRED = "KEY_EXPIRED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    TIMESTAMP_EXPIRED = "TIMESTAMP_EXPIRED"
    NONCE_REPLAYED = "NONCE_REPLAYED"
    POLICY_REJECTED = "POLICY_REJECTED"


class AgentIdentityError(ValueError):
    """输入格式或协议层面的错误。"""


class MetadataValidationError(ValueError):
    """metadata 内容不合法时抛出。"""

